import { useState, type FormEvent } from "react";
import { accountProviders, accountSummary, dateInputValue, emptyAccountProfile, factorLabel, reviewedAtFromInput, statusLabel } from "./account-security";
import { AlertIcon, CheckIcon, LockIcon, UsersIcon } from "./icons";
import { formatDate } from "./format";
import type { AccountCategory, AccountFactor, AccountProfile, AccountProfileInput, BackupCodesStatus, PasswordStatus, RecoveryStatus, TwoStepStatus } from "./types";
import { StatusChip, type Tone } from "./ui";

const categories: Array<{ value: AccountCategory; label: string }> = [
	{ value: "email", label: "Email" }, { value: "social", label: "Social" },
	{ value: "developer", label: "Developer" }, { value: "finance", label: "Finance" },
	{ value: "gaming", label: "Gaming" }, { value: "shopping", label: "Shopping" },
	{ value: "work", label: "Work" }, { value: "other", label: "Other" },
];

const factors: AccountFactor[] = ["authenticator", "passkey", "security-key", "provider-prompt", "sms", "email", "other"];

function profileTone(profile: AccountProfile): Tone {
	if (profile.status === "attention") return "attention";
	if (profile.status === "incomplete") return "unknown";
	return "healthy";
}

function profileStatus(profile: AccountProfile) {
	if (profile.status === "attention") return "Suggestions available";
	if (profile.status === "incomplete") return "Checklist incomplete";
	return "Checklist looks good";
}

function priorityTone(priority: "high" | "medium" | "low"): Tone {
	return priority === "high" ? "danger" : priority === "medium" ? "attention" : "unknown";
}

function AccountEditor({ profile, busy, save, cancel }: { profile: AccountProfileInput; busy: boolean; save: (profile: AccountProfileInput) => Promise<boolean>; cancel: () => void }) {
	const [draft, setDraft] = useState<AccountProfileInput>(() => ({ ...profile, factors: [...profile.factors] }));
	const [saving, setSaving] = useState(false);
	const toggleFactor = (factor: AccountFactor) => {
		setDraft((current) => ({ ...current, factors: current.factors.includes(factor) ? current.factors.filter((item) => item !== factor) : [...current.factors, factor] }));
	};
	const submit = async (event: FormEvent) => {
		event.preventDefault();
		setSaving(true);
		try {
			if (await save(draft)) cancel();
		} finally {
			setSaving(false);
		}
	};
	return <section className="panel account-editor" aria-labelledby="account-editor-title">
		<div className="section-heading"><div className="heading-identity"><span className="section-icon cyan"><UsersIcon /></span><div><p className="eyebrow">OWNER-REPORTED CHECKLIST</p><h2 id="account-editor-title">{draft.id ? "Edit account profile" : "Add account profile"}</h2></div></div><p>Record status—not secret contents.</p></div>
		<p className="account-secret-warning"><LockIcon size={17} /><span><strong>Never paste a password, cookie, authenticator setup link, recovery code, or private key.</strong> HAVEN has no field for those values and rejects recognizable secret formats.</span></p>
		<form onSubmit={submit} className="account-form">
			<div className="account-form-grid">
				<label>Provider or platform<input required maxLength={80} list="account-providers" value={draft.provider} onChange={(event) => setDraft({ ...draft, provider: event.target.value })} placeholder="Google, GitHub, Instagram…" /></label>
				<datalist id="account-providers">{accountProviders.map((provider) => <option key={provider} value={provider} />)}</datalist>
				<label>Profile label<input required maxLength={120} value={draft.label} onChange={(event) => setDraft({ ...draft, label: event.target.value })} placeholder="Personal, portfolio, gaming…" /></label>
				<label>Sign-in or profile identifier <small>optional</small><input maxLength={200} value={draft.identifier || ""} onChange={(event) => setDraft({ ...draft, identifier: event.target.value })} placeholder="Email or handle—not a password" /></label>
				<label>Category<select value={draft.category} onChange={(event) => setDraft({ ...draft, category: event.target.value as AccountCategory })}>{categories.map((category) => <option key={category.value} value={category.value}>{category.label}</option>)}</select></label>
				<label>Two-step verification<select value={draft.twoStepStatus} onChange={(event) => { const value = event.target.value as TwoStepStatus; setDraft({ ...draft, twoStepStatus: value, factors: value === "enabled" ? draft.factors : [] }); }}><option value="unknown">Not checked</option><option value="enabled">Enabled</option><option value="disabled">Not enabled</option><option value="not-supported">Not supported</option></select></label>
				<label>Password posture<select value={draft.passwordStatus} onChange={(event) => setDraft({ ...draft, passwordStatus: event.target.value as PasswordStatus })}><option value="unknown">Not checked</option><option value="unique">Unique</option><option value="reused">Reused</option><option value="passwordless">Passwordless</option><option value="not-applicable">Not applicable</option></select></label>
				<label>Recovery method<select value={draft.recoveryStatus} onChange={(event) => setDraft({ ...draft, recoveryStatus: event.target.value as RecoveryStatus })}><option value="unknown">Not checked</option><option value="configured">Configured</option><option value="missing">Not configured</option><option value="not-supported">Not supported</option></select></label>
				<label>Backup codes<select value={draft.backupCodesStatus} onChange={(event) => setDraft({ ...draft, backupCodesStatus: event.target.value as BackupCodesStatus })}><option value="unknown">Not checked</option><option value="stored">Stored safely elsewhere</option><option value="missing">Not generated or stored</option><option value="not-supported">Not supported</option></select></label>
				<label>Last security review <small>optional</small><input type="date" value={dateInputValue(draft.lastReviewedAt)} max={new Date().toISOString().slice(0, 10)} onChange={(event) => setDraft({ ...draft, lastReviewedAt: reviewedAtFromInput(event.target.value) })} /></label>
			</div>
			<fieldset className="account-factor-fieldset" disabled={draft.twoStepStatus !== "enabled"}><legend>Second factors in use</legend><p>{draft.twoStepStatus === "enabled" ? "Select the methods you confirmed at the provider." : "Mark two-step verification enabled to record its methods."}</p><div>{factors.map((factor) => <label key={factor}><input type="checkbox" checked={draft.factors.includes(factor)} onChange={() => toggleFactor(factor)} />{factorLabel(factor)}</label>)}</div></fieldset>
			<label className="account-notes">Notes <small>optional · encrypted at rest · maximum 4 KB</small><textarea maxLength={4096} rows={4} value={draft.notes || ""} onChange={(event) => setDraft({ ...draft, notes: event.target.value })} placeholder="Example: recovery email verified; reviewed signed-in devices. Never paste the actual secret or code." /></label>
			<div className="account-form-actions"><button type="submit" disabled={busy || saving}>{saving ? "Saving…" : "Save profile"}</button><button type="button" className="secondary-button" onClick={cancel} disabled={busy || saving}>Cancel</button></div>
		</form>
	</section>;
}

function AccountCard({ profile, demoMode, edit, remove }: { profile: AccountProfile; demoMode: boolean; edit: () => void; remove: () => void }) {
	return <article className="account-card">
		<div className="account-card-heading"><div><span className="account-avatar" aria-hidden="true">{profile.provider.slice(0, 1).toUpperCase()}</span><div><p>{profile.provider}</p><h3>{profile.label}</h3>{profile.identifier && <small>{profile.identifier}</small>}</div></div><StatusChip label={profileStatus(profile)} tone={profileTone(profile)} /></div>
		<dl className="account-posture-grid">
			<div><dt>Two-step verification</dt><dd>{statusLabel(profile.twoStepStatus)}</dd></div>
			<div><dt>Password</dt><dd>{statusLabel(profile.passwordStatus)}</dd></div>
			<div><dt>Recovery method</dt><dd>{statusLabel(profile.recoveryStatus)}</dd></div>
			<div><dt>Backup codes</dt><dd>{statusLabel(profile.backupCodesStatus)}</dd></div>
		</dl>
		<div className="account-factor-list">{profile.factors.length > 0 ? profile.factors.map((factor) => <span key={factor}>{factorLabel(factor)}</span>) : <span className="muted-factor">No second-factor method recorded</span>}</div>
		{profile.notes && <p className="account-card-notes">{profile.notes}</p>}
		{profile.suggestions.length > 0 ? <div className="account-suggestions"><h4><AlertIcon size={17} /> Suggestions</h4><ul>{profile.suggestions.map((suggestion) => <li key={suggestion.id}><StatusChip label={suggestion.priority} tone={priorityTone(suggestion.priority)} /><span><strong>{suggestion.title}</strong><small>{suggestion.summary}</small></span></li>)}</ul></div> : <p className="account-good"><CheckIcon size={18} /><span>No improvement suggestion follows from the status you recorded.</span></p>}
		<div className="account-card-footer"><small>{profile.lastReviewedAt ? `Security reviewed ${formatDate(profile.lastReviewedAt)}` : "No security review date recorded"}</small>{!demoMode && <div><button type="button" className="text-button" onClick={edit}>Edit</button><button type="button" className="text-button danger-text" onClick={remove}>Remove</button></div>}</div>
	</article>;
}

export function AccountNotebook({ profiles, demoMode, busy, save, remove }: { profiles: AccountProfile[]; demoMode: boolean; busy: boolean; save: (profile: AccountProfileInput) => Promise<boolean>; remove: (profile: AccountProfile) => void }) {
	const [editing, setEditing] = useState<AccountProfileInput | null>(null);
	const summary = accountSummary(profiles);
	return <>
		<section className="panel account-summary" aria-labelledby="account-summary-title">
			<div className="section-heading"><div className="heading-identity"><span className="section-icon green"><LockIcon /></span><div><p className="eyebrow">PRIVATE SECURITY NOTEBOOK</p><h2 id="account-summary-title">Account readiness</h2></div></div>{!demoMode && !editing && <button type="button" onClick={() => setEditing(emptyAccountProfile())}>Add account</button>}</div>
		<div className="account-metrics"><div><strong>{summary.total}</strong><small>profiles tracked</small></div><div><strong>{summary.good}</strong><small>checklists look good</small></div><div><strong>{summary.attention}</strong><small>with improvements</small></div><div><strong>{summary.incomplete}</strong><small>not fully checked</small></div></div>
		<p className="account-boundary"><strong>Owner-reported, not provider-verified.</strong> Suggestions are calm checklist guidance and never threat alerts or push notifications. Identifiers, posture choices, and notes are encrypted before SQLite storage.</p>
	</section>
		{demoMode && <p className="demo-banner" role="status"><strong>Synthetic account notebook.</strong> These invented profiles demonstrate the workflow; editing is disabled.</p>}
		{editing && <AccountEditor profile={editing} busy={busy} save={save} cancel={() => setEditing(null)} />}
		<section className="account-grid" aria-label="Account security profiles">
			{profiles.length === 0 ? <div className="panel account-empty"><UsersIcon size={30} /><h2>No account profiles yet</h2><p>Add the platforms you care about, then record only which protections are configured.</p>{!demoMode && <button type="button" onClick={() => setEditing(emptyAccountProfile())}>Add your first account</button>}</div> : profiles.map((profile) => <AccountCard key={profile.id} profile={profile} demoMode={demoMode} edit={() => setEditing({ ...profile, factors: [...profile.factors] })} remove={() => remove(profile)} />)}
		</section>
	</>;
}
