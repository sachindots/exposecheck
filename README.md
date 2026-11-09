# exposecheck

Audit listening network sockets on a Linux host and report unblocked public services or Docker port exposures.

## Why

Services often bind to `0.0.0.0` or `[::]` unintentionally. Databases, debug ports, and internal HTTP endpoints get left open to local networks or the internet.

Host firewalls like ufw, iptables, or nftables can block incoming traffic, but rule gaps leave listeners reachable. Furthermore, Docker configures its own iptables rules and publishes container ports directly on host interfaces, bypassing ufw rules entirely.

`exposecheck` checks what is open on your machine in one run. It reads listening sockets directly from the kernel via `/proc/net`, checks host firewall rules, inspects Docker port mappings, and lists findings with specific fix instructions. When findings exist, it exits with status code 1, making it suitable for CI checks and server audits.

## Install

Install with Go (version 1.22 or later):

```bash
go install github.com/sachindots/exposecheck@latest
```

Or build from source:

```bash
git clone https://github.com/sachindots/exposecheck.git
cd exposecheck
go build -o exposecheck .
```

## Usage

Run `exposecheck` directly:

```bash
exposecheck
```

Example output with open findings:

```
Listeners
  public
    tcp  0.0.0.0:8000             python3 (pid 2)
  local
    tcp  127.0.0.1:5432           python3 (pid 3)

Findings (5)
  [firewall] tcp 0.0.0.0:8000: public listener not blocked by firewall
    fix: ufw deny 8000/tcp, or bind to 127.0.0.1
  [docker] tcp 0.0.0.0:6333: container local_rag_qdrant publishes port 6333/tcp on all interfaces; Docker bypasses ufw
    fix: publish with -p 127.0.0.1:6333:6333, or filter in the DOCKER-USER chain
  [docker] tcp 0.0.0.0:6334: container local_rag_qdrant publishes port 6334/tcp on all interfaces; Docker bypasses ufw
    fix: publish with -p 127.0.0.1:6334:6334, or filter in the DOCKER-USER chain
  [docker] tcp [::]:6333: container local_rag_qdrant publishes port 6333/tcp on all interfaces; Docker bypasses ufw
    fix: publish with -p 127.0.0.1:6333:6333, or filter in the DOCKER-USER chain
  [docker] tcp [::]:6334: container local_rag_qdrant publishes port 6334/tcp on all interfaces; Docker bypasses ufw
    fix: publish with -p 127.0.0.1:6334:6334, or filter in the DOCKER-USER chain

Notes
  ufw: failed (exit status 1), skipped
```

When no risky exposures are detected:

```
Listeners
  local
    tcp  127.0.0.1:5432           python3 (pid 2)

No findings.

Notes
  ufw: failed (exit status 1), skipped
  docker: failed (exit status 1), skipped
```

Run with `sudo` to allow reading firewall rules and resolving process names owned by other users:

```bash
sudo exposecheck
```

### JSON output

Use the `--json` flag for machine-readable JSON output:

```bash
exposecheck --json
```

See [docs/exit-codes-and-json.md](docs/exit-codes-and-json.md) for exit codes and full JSON field definitions.

## How it works

1. **Scans socket tables:** Reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6` to list all TCP and UDP listening sockets.
2. **Classifies addresses:** Categorizes each listener address as `local` (loopback `127.0.0.0/8`, `::1`), `tailnet` (`100.64.0.0/10` or assigned to `tailscale0`), or `public` (all other IPs, including `0.0.0.0` and `::`).
3. **Resolves processes:** Scans `/proc/<pid>/fd/` for socket file descriptors and reads `/proc/<pid>/comm` to match socket inodes to process names and PIDs.
4. **Evaluates firewalls:** Inspects rules from `ufw status verbose`, `iptables -S`, and `nft list ruleset`. Flags any public listener not blocked by an active rule or a default drop policy.
5. **Audits Docker:** Runs `docker ps` to find containers published on `0.0.0.0` or `[::]`, warning about ports that bypass ufw.

## Limits

- **Linux only:** Requires Linux `/proc` filesystems (`/proc/net/*` and `/proc/<pid>/fd/*`).
- **Own host only:** Audits the local machine where the command runs. It does not perform remote scans across networks.
- **No remote scan:** Does not send network probes or test reachability from outside the machine.
- **No config file:** Takes only an optional `--json` flag. There is no configuration file or whitelist system.
- **No auto-fix:** Reports suggested fixes in output, but never modifies firewall rules, terminates processes, or restarts containers.
- **Firewall parsing is simple:** Only parses basic port and protocol rules in the primary input filter chain. It does not evaluate source IP restrictions, network interfaces, or custom jump chains.
- **Needs root:** Non-root users cannot read socket links in `/proc` for other users' processes, nor run firewall tools (`ufw`, `iptables`, `nft`). Run with `sudo` for full visibility.

## License

MIT. See [LICENSE](LICENSE).
