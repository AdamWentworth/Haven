#!/usr/bin/env bash
set -euo pipefail

mode="${1:-install}"
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
binary_directory="${HOME}/.local/share/haven/bin"
binary_path="${binary_directory}/haven-agent"
unit_directory="${HOME}/.config/systemd/user"

case "${mode}" in
  status)
    if [[ -x "${binary_path}" ]]; then "${binary_path}" version; else printf '{"installed":false}\n'; fi
    systemctl --user status haven-agent.timer --no-pager || true
    ;;
  uninstall)
    systemctl --user disable --now haven-agent.timer || true
    rm -f -- "${unit_directory}/haven-agent.service" "${unit_directory}/haven-agent.timer" "${binary_path}"
    systemctl --user daemon-reload
    printf 'Removed the HAVEN binary and timer; enrolled identity in ~/.local/share/haven/agent was preserved.\n'
    ;;
  install|repair)
    mkdir -p -- "${binary_directory}" "${unit_directory}" "${HOME}/.local/share/haven/agent"
    temporary_binary="${binary_path}.${$}.tmp"
    trap 'rm -f -- "${temporary_binary}"' EXIT
    if [[ -n "${HAVEN_AGENT_BINARY:-}" ]]; then
      if [[ ! "${HAVEN_AGENT_SHA256:-}" =~ ^[0-9a-fA-F]{64}$ ]]; then printf 'HAVEN_AGENT_SHA256 is required for a prebuilt binary.\n' >&2; exit 1; fi
      actual_hash="$(sha256sum -- "${HAVEN_AGENT_BINARY}" | awk '{print $1}')"
      if [[ "${actual_hash}" != "${HAVEN_AGENT_SHA256,,}" ]]; then printf 'The prebuilt agent SHA-256 does not match.\n' >&2; exit 1; fi
      cp -- "${HAVEN_AGENT_BINARY}" "${temporary_binary}"
    else
      revision="$(git -C "${repository_root}" rev-parse HEAD)"
      if [[ ! "${revision}" =~ ^[0-9a-f]{40}$ ]]; then printf 'A full Git revision is required.\n' >&2; exit 1; fi
      (cd -- "${repository_root}" && go build -trimpath -ldflags="-s -w -X github.com/AdamWentworth/haven/internal/buildinfo.Revision=${revision}" -o "${temporary_binary}" ./cmd/haven-agent)
    fi
    chmod 0755 -- "${temporary_binary}"
    mv -f -- "${temporary_binary}" "${binary_path}"
    install -m 0644 -- "${repository_root}/packaging/systemd/haven-agent.service" "${unit_directory}/haven-agent.service"
    install -m 0644 -- "${repository_root}/packaging/systemd/haven-agent.timer" "${unit_directory}/haven-agent.timer"
    systemctl --user daemon-reload
    systemctl --user enable --now haven-agent.timer
    systemctl --user start haven-agent.service
    "${binary_path}" version
    systemctl --user status haven-agent.timer --no-pager
    ;;
  *)
    printf 'Usage: %s [install|repair|status|uninstall]\n' "$0" >&2
    exit 2
    ;;
esac
