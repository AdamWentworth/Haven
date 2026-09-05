import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { registerApplicationServiceWorker } from "./desktop-install";
import "./styles.css";

const root = document.querySelector<HTMLDivElement>("#root");
if (!root) {
  throw new Error("HAVEN could not find its application root.");
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

void registerApplicationServiceWorker().catch(() => {
	// Installation is optional; notification enrollment reports its own errors.
});
