'use strict';

const { app, BrowserWindow, dialog, session } = require('electron');
const { spawn } = require('node:child_process');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');

app.setName('WireScope');
app.commandLine.appendSwitch('disable-background-networking');
app.commandLine.appendSwitch('disable-component-update');
app.commandLine.appendSwitch('disable-domain-reliability');
app.commandLine.appendSwitch('no-pings');

let backend = null;
let apiPort = null;
let quitting = false;
let mainWindow = null;

function reserveLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
      const address = server.address();
      const port = address && typeof address === 'object' ? address.port : null;
      server.close(error => error ? reject(error) : resolve(port));
    });
  });
}

function executablePath() {
  const filename = process.platform === 'win32' ? 'wirescope-backend.exe' : 'wirescope-backend';
  return path.join(process.resourcesPath, 'bin', filename);
}

function startBackend(port) {
  if (app.isPackaged) {
    const exe = executablePath();
    backend = spawn(exe, ['--port', String(port)], {
      stdio: 'ignore',
      windowsHide: true,
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
    });
  } else {
    const python = process.env.WIRESCOPE_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
    const projectRoot = app.getAppPath();
    backend = spawn(python, ['-m', 'wirescope', '--port', String(port)], {
      cwd: projectRoot,
      stdio: 'ignore',
      windowsHide: true,
      env: {
        ...process.env,
        PYTHONPATH: [path.join(projectRoot, 'src'), process.env.PYTHONPATH || ''].filter(Boolean).join(path.delimiter),
        PYTHONUNBUFFERED: '1',
      },
    });
  }

  backend.once('error', error => {
    if (quitting) return;
    dialog.showErrorBox('WireScope backend failed', `Could not start the local backend (${error.message}).\n\nFor source development, install the Python dependencies documented in README.md.`);
    app.quit();
  });
  backend.once('exit', (code, signal) => {
    if (quitting || code === 0) return;
    dialog.showErrorBox('WireScope backend stopped', `The local backend exited unexpectedly (code ${code ?? 'unknown'}, signal ${signal ?? 'none'}).`);
    app.quit();
  });
}

async function waitForBackend(port) {
  const healthUrl = `http://127.0.0.1:${port}/api/health`;
  const deadline = Date.now() + 15000;
  let lastError = null;
  while (Date.now() < deadline) {
    if (!backend || backend.exitCode !== null) {
      throw new Error('Backend process exited before the local API became ready.');
    }
    try {
      const response = await fetch(healthUrl, { cache: 'no-store', signal: AbortSignal.timeout(600) });
      if (response.ok) {
        const body = await response.json();
        if (body && body.ok === true && body.app === 'WireScope') return;
      }
      lastError = new Error(`health check returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise(resolve => setTimeout(resolve, 120));
  }
  throw new Error(`Local backend did not become ready: ${lastError ? lastError.message : 'timeout'}`);
}

function createWindow(port) {
  const trustedOrigin = `http://127.0.0.1:${port}`;
  mainWindow = new BrowserWindow({
    width: 1500,
    height: 960,
    minWidth: 1080,
    minHeight: 680,
    show: false,
    title: 'WireScope',
    backgroundColor: '#0b0f17',
    autoHideMenuBar: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      devTools: !app.isPackaged,
    },
  });

  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event, destination) => {
    try {
      if (new URL(destination).origin !== trustedOrigin) event.preventDefault();
    } catch {
      event.preventDefault();
    }
  });
  mainWindow.webContents.on('will-redirect', (event, destination) => {
    try {
      if (new URL(destination).origin !== trustedOrigin) event.preventDefault();
    } catch {
      event.preventDefault();
    }
  });
  mainWindow.once('ready-to-show', () => mainWindow && mainWindow.show());
  mainWindow.on('closed', () => { mainWindow = null; });
  return mainWindow.loadURL(trustedOrigin);
}

app.whenReady().then(async () => {
  // No application network requests other than the local backend. Deny web permissions.
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  try {
    apiPort = await reserveLoopbackPort();
    if (!Number.isInteger(apiPort)) throw new Error('Could not reserve a local API port.');
    startBackend(apiPort);
    await waitForBackend(apiPort);
    await createWindow(apiPort);
  } catch (error) {
    dialog.showErrorBox('Could not start WireScope', String(error && error.message ? error.message : error));
    app.quit();
  }
});

app.on('before-quit', () => {
  quitting = true;
  if (backend && backend.exitCode === null) {
    try { backend.kill('SIGTERM'); } catch { /* Process may already be exiting. */ }
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (mainWindow === null && Number.isInteger(apiPort)) createWindow(apiPort).catch(() => app.quit());
});
