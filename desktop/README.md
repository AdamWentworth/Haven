# HAVEN desktop application

This directory contains HAVEN's native Electron client. It opens the private HTTPS
hub in a dedicated operating-system window without embedding a second dashboard,
running another endpoint agent, or exposing Node.js, preload, IPC, filesystem, or
shell APIs to the remotely delivered UI.

The renderer uses current Chromium with WebAuthn support, an application-specific
persistent session, encrypted cookies in packaged builds, process sandboxing, and
no browser extensions. Top-level navigation is limited to one exact HTTPS origin
selected when the application is built; popup windows, webviews, insecure content,
downloads, developer tools, and every permission except an explicitly confirmed
HAVEN notification request are denied. An installed client cannot be redirected by
changing a runtime environment variable.

## Local verification

```powershell
cd desktop
npm ci
npm test
npm run check
```

Run the development client with `npm start`. Build a current-user Windows installer
with `npm run dist:windows`. Both commands generate the pinned origin module first.
The conventional default is `https://haven.home.arpa:8443/`; select another private
origin at build time when necessary:

```powershell
$env:HAVEN_DESKTOP_ORIGIN = "https://security.home.arpa:9443"
npm run dist:windows
```

The value must be one HTTPS origin with no credentials, path, query, or fragment.
Install the desktop client only on workstations where a dedicated console is useful;
endpoint agents and ordinary browser access do not require it.

The installer is unsigned during pre-release development, so Windows may identify
the publisher as unknown. Public distribution should add code signing before the
desktop package is described as generally trusted.
