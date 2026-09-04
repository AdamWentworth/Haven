import { useState } from "react";
import { HavenIcon } from "./icons";
import type { AuthStatus } from "./types";

export function AuthenticationGate({ status, authenticate }: { status: AuthStatus; authenticate: (bootstrapCode?: string, label?: string) => Promise<void> }) {
	const [bootstrapCode, setBootstrapCode] = useState("");
	const [label, setLabel] = useState("This device");
	const [useLocalCode, setUseLocalCode] = useState(!status.configured);
	const [working, setWorking] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const passkeysSupported = typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;

	const proceed = async () => {
		setWorking(true);
		setError(null);
		try {
			await authenticate(useLocalCode ? bootstrapCode.trim() : undefined, label.trim());
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "The passkey provider could not complete the request.");
		} finally {
			setWorking(false);
		}
	};

	if (status.useConfiguredOrigin) {
		return <main className="auth-shell"><section className="auth-card"><span className="brand-mark"><HavenIcon /></span><p className="eyebrow">TRUSTED PRIVATE ORIGIN</p><h1>Open HAVEN at its trusted address</h1><p>Passkeys require HAVEN's exact configured origin. Your data stays on your private network; only the browser address changes.</p><a className="primary-action" href={status.origin}>Continue to {status.origin}</a></section></main>;
	}

	return (
		<main className="auth-shell">
			<section className="auth-card" aria-labelledby="auth-title">
				<span className="brand-mark"><HavenIcon /></span>
				<p className="eyebrow">HAVEN ACTION CENTER</p>
				<h1 id="auth-title">{useLocalCode ? (status.configured ? "Recover passkey access" : "Create the first owner passkey") : "Unlock with a passkey"}</h1>
				<p>{useLocalCode ? "Generate a short-lived enrollment code on the machine that hosts HAVEN, then paste it here. This is required only to create or recover owner access—not whenever HAVEN starts." : "Use any passkey already registered to HAVEN. Your browser and operating system choose the available provider, such as Windows Hello, Touch ID, a phone, or a hardware security key."}</p>
				{useLocalCode && <><label className="auth-field"><span>Passkey label</span><input value={label} maxLength={60} onChange={(event) => setLabel(event.target.value)} autoComplete="off" /></label><label className="auth-field"><span>One-time enrollment code</span><input value={bootstrapCode} onChange={(event) => setBootstrapCode(event.target.value)} autoComplete="one-time-code" spellCheck={false} /></label></>}
				{error && <p className="inline-error" role="alert">{error}</p>}
				{!passkeysSupported && <p className="inline-error" role="alert">This browser does not expose the passkey APIs HAVEN needs.</p>}
				<button className="primary-action" type="button" onClick={() => void proceed()} disabled={working || !passkeysSupported || (useLocalCode && bootstrapCode.trim() === "")}>{working ? "Waiting for your passkey provider…" : useLocalCode ? "Create HAVEN passkey" : "Continue with a passkey"}</button>
				{status.configured && <button className="text-action" type="button" onClick={() => { setUseLocalCode((value) => !value); setError(null); }}>{useLocalCode ? "Return to passkey sign-in" : "Lost access? Use a local recovery code"}</button>}
				<p className="auth-footnote">No HAVEN password is stored. A trusted-browser session lasts up to 30 days; sensitive controls still require a fresh passkey confirmation.</p>
			</section>
		</main>
	);
}
