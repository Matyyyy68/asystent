const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('sentinel', { call: (method, data = {}) => ipcRenderer.invoke('sentinel', method, data) });
