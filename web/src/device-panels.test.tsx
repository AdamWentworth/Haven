// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ActivityPanel, BaselinePanel, ConnectionsPanel, DefenderPanel, FindingsPanel, FirewallPanel, LinuxPanel } from "./device-panels";
import type { BaselineCheck, DefenderStatus, HavenAlert, LinuxBaseline, NetworkConnection, SecurityEvent, SecurityFinding } from "./types";

afterEach(cleanup);

describe("device evidence panels", () => {
	it("keeps unavailable Defender evidence distinct from verified healthy values", () => {
		const { rerender } = render(<DefenderPanel defender={null} />);
		expect(screen.getByText("Defender status is unavailable.")).toBeInTheDocument();

		const defender: DefenderStatus = {
			antivirusEnabled: true,
			realTimeProtectionEnabled: true,
			behaviorMonitorEnabled: true,
			downloadProtectionEnabled: true,
			tamperProtected: true,
			signatureVersion: "1.2.3",
			signatureUpdatedAt: "2026-09-07T12:00:00Z",
			lastQuickScanAt: null,
			lastFullScanAt: null,
		};
		rerender(<DefenderPanel defender={defender} />);
		expect(screen.getAllByText("On")).toHaveLength(3);
		expect(screen.getByText(/1\.2\.3/)).toBeInTheDocument();
		expect(screen.getAllByText("Not reported")).toHaveLength(2);
	});

	it("describes Linux posture and inactive firewall policy without inventing enforcement", () => {
		const baseline: LinuxBaseline = {
			updates: { pendingPackageCount: 2, pendingSecurityPackageCount: 0, pendingReboot: false },
			firewall: { provider: "UFW", active: false },
			ssh: { serverRunning: true, passwordAuthentication: "no", keyboardInteractiveAuthentication: "no", permitRootLogin: "prohibit-password", publicKeyAuthentication: "yes", failedLoginCount24Hours: 0 },
			services: { failedUnitCount: 0, failedUnits: [] },
			automaticUpdates: { enabled: true, active: true },
			appArmor: { enabled: true },
			timeSync: { synchronized: true },
			storage: { mountPoint: "/", capacityBytes: 1000, availableBytes: 750, usedPercentage: 25 },
			workloads: null,
		};
		render(<><LinuxPanel baseline={baseline} /><FirewallPanel profiles={[{ name: "UFW", enabled: false, defaultInboundAction: "deny", defaultOutboundAction: "allow" }]} isLinux /></>);
		expect(screen.getByText("Ubuntu host posture")).toBeInTheDocument();
		expect(screen.getByText("Configured inbound default (inactive)")).toBeInTheDocument();
		expect(screen.getByText("Configured outbound default (inactive)")).toBeInTheDocument();
	});

	it("groups duplicate listener sockets and saves an owner-constrained expectation", async () => {
		const saveExpectation = vi.fn();
		const connections: NetworkConnection[] = [
			{ protocol: "TCP", localAddress: "0.0.0.0", localPort: 22, remoteAddress: "0.0.0.0", remotePort: 0, state: "Listen", processId: 100, processName: "sshd", systemdUnit: "ssh.service" },
			{ protocol: "TCP", localAddress: "::", localPort: 22, remoteAddress: "::", remotePort: 0, state: "Listen", processId: 100, processName: "sshd", systemdUnit: "ssh.service" },
		];
		const user = userEvent.setup();
		render(<ConnectionsPanel deviceId="device-test" operatingSystem="Ubuntu" connections={connections} workloads={null} expectedServices={[]} observations={[]} saveExpectation={saveExpectation} saveExpectations={vi.fn()} removeExpectation={vi.fn()} busy={false} />);
		expect(screen.getByText(/1 logical service endpoint from 2 raw sockets/)).toBeInTheDocument();
		expect(screen.getByText(/2 raw sockets grouped/)).toBeInTheDocument();
		await user.click(screen.getByRole("button", { name: "Mark expected…" }));
		const listenerLabel = screen.getAllByLabelText("Friendly label")[0];
		await user.clear(listenerLabel);
		await user.type(listenerLabel, "SSH administration");
		await user.click(screen.getByRole("button", { name: "Save expectation" }));
		expect(saveExpectation).toHaveBeenCalledWith(expect.objectContaining({ deviceId: "device-test", label: "SSH administration", protocol: "TCP", port: 22, bindScope: "wildcard", processNames: ["sshd"], systemdUnits: ["ssh.service"] }));
	});

	it("renders clear posture separately from lifecycle history", () => {
		const checks: BaselineCheck[] = [{ id: "firewall", category: "Network", title: "Host firewall", status: "pass", summary: "Enabled", evidence: "All profiles" }];
		render(<><FindingsPanel findings={[]} checks={checks} reviews={[]} review={vi.fn()} /><BaselinePanel checks={checks} collectedAt="2026-09-07T12:00:00Z" platform="Windows" /><ActivityPanel events={[]} alerts={[]} /></>);
		expect(screen.getByText("No actionable findings")).toBeInTheDocument();
		expect(screen.getByText("Posture checks")).toBeInTheDocument();
		expect(screen.getByText("No posture changes recorded yet.")).toBeInTheDocument();
	});

	it("shows an active finding lifecycle without calling it an attack", () => {
		const finding: SecurityFinding = { id: "updates", category: "Maintenance", title: "Updates available", severity: "medium", summary: "One verified update is pending.", recommendation: "Review the native updater." };
		const event: SecurityEvent = { id: 1, deviceId: "device-test", deviceName: "TEST-DEVICE", findingId: finding.id, kind: "opened", category: finding.category, title: finding.title, severity: finding.severity, summary: finding.summary, occurredAt: "2026-09-07T12:00:00Z" };
		const alert: HavenAlert = { id: "finding:device-test:updates", instanceId: "finding:device-test:updates:1", deviceId: "device-test", deviceName: "TEST-DEVICE", kind: "finding", severity: "medium", title: finding.title, summary: finding.summary, evidence: "Verified by the synthetic fixture.", startedAt: event.occurredAt };
		render(<><FindingsPanel findings={[finding]} checks={[]} reviews={[]} review={vi.fn()} /><ActivityPanel events={[event]} alerts={[alert]} /></>);
		expect(screen.getByText("1 finding to review")).toBeInTheDocument();
		expect(screen.getByText("Currently active.")).toBeInTheDocument();
		expect(screen.queryByText(/attack occurred/i)).not.toBeInTheDocument();
	});
});
