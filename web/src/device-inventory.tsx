import { DevicesIcon, LaptopIcon, MonitorIcon, ServerIcon } from "./icons";
import { formatRelativeTime } from "./format";
import type { DeviceRecord } from "./types";
import { StatusChip, type Tone } from "./ui";

export function DeviceInventory({ devices, selectedId, select, demoMode }: { devices: DeviceRecord[]; selectedId: string; select: (id: string) => void; demoMode: boolean }) {
	return (
		<section className="device-inventory" aria-labelledby="devices-title">
			<div className="inventory-heading">
				<div className="heading-identity"><span className="section-icon cyan"><DevicesIcon /></span><div><p className="eyebrow">{demoMode ? "SYNTHETIC INVENTORY" : "TRUSTED INVENTORY"}</p><h2 id="devices-title">{demoMode ? "Demo devices" : "Devices"}</h2></div></div>
				<span>{devices.length} known</span>
			</div>
			<div className="device-list">
				{devices.map((device) => {
					const tone: Tone = device.status === "current" ? "healthy" : device.status === "revoked" ? "danger" : "attention";
					return (
						<button className={`device-button ${selectedId === device.id ? "selected" : ""}`} type="button" key={device.id} onClick={() => select(device.id)} aria-pressed={selectedId === device.id}>
							<span className="device-identity"><span className="device-icon">{device.operatingSystem.toLowerCase().includes("server") ? <ServerIcon /> : device.displayName.toLowerCase().includes("laptop") ? <LaptopIcon /> : <MonitorIcon />}</span><span><strong>{device.displayName}</strong><small>{device.operatingSystem || "Awaiting first report"}{device.lastCollectedAt ? ` · reported ${formatRelativeTime(device.lastCollectedAt)}` : ""}</small></span></span>
							<StatusChip label={device.status.replaceAll("-", " ")} tone={tone} />
						</button>
					);
				})}
			</div>
		</section>
	);
}
