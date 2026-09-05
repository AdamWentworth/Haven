"use strict";

const { app, BrowserWindow, dialog, Menu, session } = require("electron");
const path = require("node:path");
const { DESKTOP_VERSION, HAVEN_URL, desktopUserAgent, isHavenUrl } = require("./security.cjs");

const PARTITION = "persist:haven";
const APPLICATION_ID = "com.adamwentworth.haven";
let mainWindow = null;
let sessionConfigured = false;
let notificationPermissionGranted = false;

app.enableSandbox();
if (process.platform === "win32") app.setAppUserModelId(APPLICATION_ID);

function secureSession(appSession) {
  if (sessionConfigured) return;
  sessionConfigured = true;

  appSession.setPermissionCheckHandler((_webContents, permission, requestingOrigin) => (
    notificationPermissionGranted && permission === "notifications" && isHavenUrl(requestingOrigin)
  ));

  appSession.setPermissionRequestHandler(async (webContents, permission, callback, details) => {
    const requestingUrl = details.requestingUrl || webContents.getURL();
    if (permission !== "notifications" || !isHavenUrl(requestingUrl)) {
      callback(false);
      return;
    }
    try {
      const parent = BrowserWindow.fromWebContents(webContents) || undefined;
      const result = await dialog.showMessageBox(parent, {
        type: "question",
        title: "Enable HAVEN alerts?",
        message: "Allow this HAVEN desktop app to show security-review notifications?",
        detail: "Notifications contain only the device label, severity, and a prompt to open HAVEN—not finding details.",
        buttons: ["Allow", "Not now"],
        defaultId: 0,
        cancelId: 1,
        noLink: true,
      });
      notificationPermissionGranted = result.response === 0;
      callback(notificationPermissionGranted);
    } catch {
      callback(false);
    }
  });

  appSession.on("will-download", (event) => event.preventDefault());
  appSession.on("select-webauthn-account", async (_event, details, callback) => {
    let credentialId = null;
    try {
      if (details.accounts.length === 1) {
        credentialId = details.accounts[0].credentialId;
      } else if (details.accounts.length > 1) {
        const labels = details.accounts.map((account, index) => account.displayName || account.name || `Passkey ${index + 1}`);
        const result = await dialog.showMessageBox(mainWindow || undefined, {
          type: "question",
          title: "Choose a HAVEN passkey",
          message: "Which passkey should HAVEN use?",
          buttons: [...labels, "Cancel"],
          defaultId: 0,
          cancelId: labels.length,
          noLink: true,
        });
        if (result.response < details.accounts.length) credentialId = details.accounts[result.response].credentialId;
      }
    } finally {
      callback(credentialId);
    }
  });
}

function createWindow() {
  const appSession = session.fromPartition(PARTITION, { cache: true });
  secureSession(appSession);

  const window = new BrowserWindow({
    title: "HAVEN",
    width: 1280,
    height: 820,
    minWidth: 840,
    minHeight: 620,
    show: false,
    autoHideMenuBar: true,
    backgroundColor: "#08100d",
    icon: path.join(__dirname, "build", "icon.ico"),
    webPreferences: {
      partition: PARTITION,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      webviewTag: false,
      devTools: false,
      navigateOnDragDrop: false,
      safeDialogs: true,
      spellcheck: false,
    },
  });

  window.webContents.setUserAgent(desktopUserAgent(window.webContents.getUserAgent()));
  window.webContents.on("will-navigate", (event, navigationUrl) => {
    if (!isHavenUrl(navigationUrl)) event.preventDefault();
  });
  window.webContents.on("will-redirect", (event, navigationUrl) => {
    if (!isHavenUrl(navigationUrl)) event.preventDefault();
  });
  window.webContents.on("will-attach-webview", (event) => event.preventDefault());
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.once("ready-to-show", () => window.show());
  window.on("closed", () => {
    if (mainWindow === window) mainWindow = null;
  });

  void window.loadURL(HAVEN_URL).catch(async () => {
    await dialog.showMessageBox(window, {
      type: "error",
      title: "HAVEN is unavailable",
      message: "The HAVEN hub could not be reached.",
      detail: "Confirm this device is connected to the home network or WireGuard, then reopen HAVEN.",
    });
    window.close();
  });
  mainWindow = window;
  return window;
}

const hasSingleInstanceLock = app.requestSingleInstanceLock();
if (!hasSingleInstanceLock) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  });

  app.whenReady().then(() => {
    Menu.setApplicationMenu(null);
    createWindow();
  });

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });

  app.on("window-all-closed", () => app.quit());
}

module.exports = { APPLICATION_ID, DESKTOP_VERSION, PARTITION };
