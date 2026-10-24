import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { once } from 'node:events';
import { asyncBufferFromUrl, parquetReadObjects } from 'hyparquet';
import { compressors } from 'hyparquet-compressors';

const DATASET = 'phreshphish/phreshphish';
const EXPECTED_DATASET_REVISION = 'eca603e0ecd4f698f8d4d226c088659e72681239';
const EXPECTED_ROWS = 498_255;
const EXPECTED_BENIGN = 276_729;
const EXPECTED_PHISH = 221_526;
const EXPECTED_PARQUET_BYTES = 27_400_613_420;
const outputPath = process.argv[2];
if (!outputPath) throw new Error('Pass a temporary CSV path.');

const transfer = { requests: 0, bytes: 0 };
const fetchOriginal = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const inputUrl = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
  const inputHeaders = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
  const isParquet = inputUrl.pathname.endsWith('.parquet');
  if (isParquet && !inputHeaders.has('range')) throw new Error('Refusing a Parquet request without an HTTP Range header.');
  const response = await fetchOriginal(input, init);
  if (!isParquet) return response;
  if (response.status !== 206) {
    await response.body?.cancel();
    throw new Error(`Parquet server ignored HTTP Range (status ${response.status}); full-file transfer refused.`);
  }
  const contentLength = Number(response.headers.get('content-length') ?? 0);
  if (contentLength > 16 * 1024 * 1024) {
    await response.body?.cancel();
    throw new Error('A single Parquet range exceeded the 16 MiB safety cap.');
  }
  const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(response.headers.get('content-range') ?? '');
  if (!match) {
    await response.body?.cancel();
    throw new Error('Parquet range response did not include a valid Content-Range header.');
  }
  transfer.requests++;
  transfer.bytes += Number(match[2]) - Number(match[1]) + 1;
  return response;
};

const datasetResponse = await fetchOriginal(`https://huggingface.co/api/datasets/${DATASET}`);
if (!datasetResponse.ok) throw new Error(`Dataset metadata request failed: HTTP ${datasetResponse.status}`);
const dataset = await datasetResponse.json();
if (dataset.sha !== EXPECTED_DATASET_REVISION || dataset.cardData?.license !== 'cc-by-4.0') {
  throw new Error('Dataset revision or anti-phishing research license changed; refusing extraction.');
}

const parquetResponse = await fetchOriginal(`https://datasets-server.huggingface.co/parquet?dataset=${encodeURIComponent(DATASET)}`);
if (!parquetResponse.ok) throw new Error(`Parquet metadata request failed: HTTP ${parquetResponse.status}`);
const manifest = await parquetResponse.json();
if (manifest.partial) throw new Error('The dataset viewer only exposes a partial Parquet conversion.');
const files = manifest.parquet_files.filter(file => file.split === 'train').sort((a, b) => a.filename.localeCompare(b.filename));
if (files.length !== 56 || files.reduce((sum, file) => sum + file.size, 0) !== EXPECTED_PARQUET_BYTES) {
  throw new Error('The PhreshPhish train Parquet manifest changed; refusing extraction.');
}

const output = createWriteStream(outputPath, { flags: 'wx', encoding: 'utf8' });
const csvHash = createHash('sha256');
const recordHash = createHash('sha256');
let rowsWritten = 0;
const counts = { benign: 0, phish: 0 };
async function writeCsv(values) {
  const line = values.map(value => `"${String(value).replaceAll('"', '""')}"`).join(',') + '\n';
  csvHash.update(line, 'utf8');
  if (!output.write(line)) await once(output, 'drain');
}

try {
  await writeCsv(['sha256', 'url', 'label']);
  for (const file of files) {
    const parquet = await asyncBufferFromUrl({ url: file.url, byteLength: file.size });
    const rows = await parquetReadObjects({ file: parquet, columns: ['sha256', 'url', 'label'], compressors });
    for (const row of rows) {
      if (typeof row.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(row.sha256) ||
          typeof row.url !== 'string' || row.url.length === 0 ||
          !['benign', 'phish'].includes(row.label)) {
        throw new Error(`Invalid URL/label/date row in ${file.filename}; row contents are not logged.`);
      }
      recordHash.update(row.sha256.toLowerCase() + '\n', 'utf8');
      counts[row.label]++;
      rowsWritten++;
      await writeCsv([row.sha256.toLowerCase(), row.url, row.label]);
    }
  }
  await new Promise((resolve, reject) => output.end(error => error ? reject(error) : resolve()));
} catch (error) {
  output.destroy();
  throw error;
}

if (rowsWritten !== EXPECTED_ROWS || counts.benign !== EXPECTED_BENIGN || counts.phish !== EXPECTED_PHISH) {
  throw new Error(`Unexpected train rows or labels: rows=${rowsWritten}, benign=${counts.benign}, phish=${counts.phish}.`);
}
const finalResponse = await fetchOriginal(`https://huggingface.co/api/datasets/${DATASET}`);
const finalDataset = await finalResponse.json();
if (!finalResponse.ok || finalDataset.sha !== EXPECTED_DATASET_REVISION) {
  throw new Error('Dataset revision changed during extraction; discard the temporary CSV.');
}
console.log(JSON.stringify({
  dataset: DATASET,
  datasetRevision: EXPECTED_DATASET_REVISION,
  license: 'cc-by-4.0; anti-phishing research use only',
  split: 'train',
  parquetFiles: files.length,
  parquetBytesTotal: EXPECTED_PARQUET_BYTES,
  rows: rowsWritten,
  counts,
  rangeRequests: transfer.requests,
  rangeBytes: transfer.bytes,
  recordIdsSha256: recordHash.digest('hex').toUpperCase(),
  extractedCsvSha256: csvHash.digest('hex').toUpperCase()
}));
