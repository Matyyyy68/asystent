'use strict';

async function quarantineDownloadedFile({ dialog, window, call, downloadsPath, eventId }) {
  if (!Number.isSafeInteger(eventId) || eventId <= 0) throw new Error('Nieprawidłowe zdarzenie do kwarantanny.');
  const confirmation = await dialog.showMessageBox(window, {
    type: 'warning', buttons: ['Anuluj', 'Wybierz plik'], defaultId: 0, cancelId: 0, noLink: true,
    message: 'Przenieść pasujący plik z Downloads do kwarantanny Sentinel AI?',
    detail: 'Sentinel sprawdzi ponownie jego SHA-256 względem wykrycia. Plik nie zostanie uruchomiony ani usunięty. Z kwarantanny będzie można go przywrócić.'
  });
  if (confirmation.response !== 1) return null;
  const choice = await dialog.showOpenDialog(window, { title: 'Wybierz plik z Downloads do kwarantanny', defaultPath: downloadsPath, properties: ['openFile'] });
  if (choice.canceled || !choice.filePaths[0]) return null;
  const result = await call('quarantineDownloadedFile', { eventId, path: choice.filePaths[0] });
  await dialog.showMessageBox(window, { type: 'info', buttons: ['OK'], title: 'Sentinel AI — kwarantanna',
    message: `Przeniesiono plik „${String(result?.fileName || '').slice(0, 180)}” do kwarantanny.`,
    detail: 'Możesz go przywrócić z tego zdarzenia. Sentinel nie uruchomił pliku.' });
  return result;
}

async function restoreDownloadedFile({ dialog, window, call, eventId }) {
  if (typeof eventId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(eventId))
    throw new Error('Nieprawidłowe zdarzenie do przywrócenia.');
  const confirmation = await dialog.showMessageBox(window, {
    type: 'warning', buttons: ['Anuluj', 'Przywróć plik'], defaultId: 0, cancelId: 0, noLink: true,
    message: 'Przywrócić plik z kwarantanny do pierwotnego folderu Downloads?',
    detail: 'Plik pozostanie nieuruchomiony. Sentinel sprawdzi jego SHA-256 i nie nadpisze istniejącego pliku.'
  });
  if (confirmation.response !== 1) return null;
  const result = await call('restoreDownloadedFile', { eventId });
  await dialog.showMessageBox(window, { type: 'info', buttons: ['OK'], title: 'Sentinel AI — plik przywrócony',
    message: `Przywrócono „${String(result?.fileName || '').slice(0, 180)}”.`,
    detail: 'Przywrócenie nie oznacza, że plik jest bezpieczny. Sentinel go nie uruchomił.' });
  return result;
}

module.exports = { quarantineDownloadedFile, restoreDownloadedFile };
