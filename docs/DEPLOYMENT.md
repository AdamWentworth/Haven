# Hub deployment

The checked-in Compose definition is a secure baseline for the Ubuntu application server, not a local-development requirement or a complete household deployment. Docker is not used to run HAVEN on development workstations. Agent ingestion and passkey authentication are implemented, but the container listener remains unpublished; private HTTPS/routing, recovery, resource, and backup decisions are still required.

## Baseline

```sh
cp .env.example .env
docker compose build --pull
docker compose up -d
docker compose ps
```

The published port is bound to host loopback. Do not change it to an all-interface binding merely to make the dashboard reachable. Add private access through a TLS reverse proxy or VPN and set `HAVEN_PUBLIC_ORIGIN` to the exact externally visible private HTTPS origin. WebAuthn and anti-forgery validation intentionally reject a different origin.

## Persistent data

SQLite and its WAL files live together in the `haven-data` volume. Do not place this volume on NFS or another network filesystem.

Use `haven-hub backup --to <new-path>` for a consistent SQLite backup while the hub is running. The destination must be a new path on protected storage. Test restoration separately; a backup that has never been restored is only an assumption. Back up the PKI directory separately because it is not part of the database.

Removing the container does not remove the named volume. Removing the volume deletes the observation history and should be treated as a destructive operation.

## Updates

Review dependency and image changes, rebuild the image, run the checks, and then recreate the service. Do not use an unreviewed floating image updater for a security control plane.

## Native agents

Endpoint agents run directly under Windows Service Control Manager, systemd, or launchd with the smallest privileges their collectors require. Do not give the hub container host namespaces, broad mounts, devices, or the Docker socket in an attempt to make it an agent.
