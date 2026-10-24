import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { once } from 'node:events';
import { asyncBufferFromUrl, parquetReadObjects } from 'hyparquet';
import { compressors } from 'hyparquet-compressors';

const DATASET = 'phreshphish/phreshphish';
const EXPECTED_DATASET_REVISION = 'eca603e0ecd4f698f8d4d226c088659e72681239';
const EXPECTED_ROWS = 168_060;
const EXPECTED_PARQUET_BYTES = 9_175_760_158;
const outputPath = process.argv[2];
if (!outputPath) throw new Error('Pass an output CSV path under the system temporary directory.');

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
  const range = response.headers.get('content-range') ?? '';
  const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(range);
  if (!match) {
    await response.body?.cancel();
    throw new Error('Parquet range response did not include a valid Content-Range header.');
  }
  transfer.requests++;
  transfer.bytes += Number(match[2]) - Number(match[1]) + 1;
  return response;
};

const revisionResponse = await fetchOriginal(`https://huggingface.co/api/datasets/${DATASET}`);
if (!revisionResponse.ok) throw new Error(`Dataset metadata request failed: HTTP ${revisionResponse.status}`);
const revision = await revisionResponse.json();
if (revision.sha !== EXPECTED_DATASET_REVISION) throw new Error(`Dataset revision changed: expected ${EXPECTED_DATASET_REVISION}, got ${revision.sha}`);

const parquetResponse = await fetchOriginal(`https://datasets-server.huggingface.co/parquet?dataset=${encodeURIComponent(DATASET)}`);
if (!parquetResponse.ok) throw new Error(`Parquet metadata request failed: HTTP ${parquetResponse.status}`);
const parquetManifest = await parquetResponse.json();
if (parquetManifest.partial) throw new Error('The dataset viewer only exposes a partial Parquet conversion.');
const files = parquetManifest.parquet_files
  .filter(file => file.split === 'test')
  .sort((left, right) => left.filename.localeCompare(right.filename));
if (files.length !== 21 || files.reduce((sum, file) => sum + file.size, 0) !== EXPECTED_PARQUET_BYTES) {
  throw new Error('The PhreshPhish test Parquet manifest changed; refusing evaluation.');
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
  await writeCsv(['url', 'label', 'split', 'record_sha256']);
  for (let index = 0; index < files.length; index++) {
    const file = files[index];
    const parquet = await asyncBufferFromUrl({ url: file.url, byteLength: file.size });
    const rows = await parquetReadObjects({
      file: parquet,
      columns: ['sha256', 'url', 'label'],
      ...(index === 0 ? { rowStart: 1 } : {}),
      compressors
    });
    for (const row of rows) {
      if (typeof row.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(row.sha256) ||
          typeof row.url !== 'string' || row.url.length === 0 ||
          !['benign', 'phish'].includes(row.label)) {
        throw new Error(`Invalid URL/label row in ${file.filename}; row contents are not logged.`);
      }
      recordHash.update(row.sha256.toLowerCase() + '\n', 'utf8');
      counts[row.label]++;
      rowsWritten++;
      await writeCsv([row.url, row.label, 'test', row.sha256.toLowerCase()]);
    }
  }
  await new Promise((resolve, reject) => output.end(error => error ? reject(error) : resolve()));
} catch (error) {
  output.destroy();
  throw error;
}

if (rowsWritten !== EXPECTED_ROWS - 1 || counts.benign + counts.phish !== rowsWritten) {
  throw new Error(`Expected ${EXPECTED_ROWS - 1} rows after excluding test row 0; extracted ${rowsWritten}.`);
}
const finalRevisionResponse = await fetchOriginal(`https://huggingface.co/api/datasets/${DATASET}`);
const finalRevision = await finalRevisionResponse.json();
if (!finalRevisionResponse.ok || finalRevision.sha !== EXPECTED_DATASET_REVISION) {
  throw new Error('Dataset revision changed during extraction; discard the temporary CSV.');
}
console.log(JSON.stringify({
  dataset: DATASET,
  datasetRevision: EXPECTED_DATASET_REVISION,
  split: 'test',
  excludedRows: 1,
  parquetFiles: files.length,
  parquetBytesTotal: EXPECTED_PARQUET_BYTES,
  rows: rowsWritten,
  counts,
  rangeRequests: transfer.requests,
  rangeBytes: transfer.bytes,
  recordIdsSha256: recordHash.digest('hex').toUpperCase(),
  extractedCsvSha256: csvHash.digest('hex').toUpperCase()
}));
