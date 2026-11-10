# exposecheck

Audit listening network sockets on a Linux host and report unblocked public services or Docker port exposures. See [docs/showcase/showcase.html](docs/showcase/showcase.html) for a terminal demo.

## Why

Services often bind to `0.0.0.0` or `[::]` unintentionally. Databases, debug ports, and internal HTTP endpoints get left open to local networks or the internet.

Host firewalls like ufw, iptables, or nftables can block incoming traffic, but rule gaps leave listeners reachable. Docker configures its own iptables rules and publishes container ports directly on host interfaces, bypassing ufw rules entirely.

`exposecheck` checks what is open on your machine in one run. It reads listening sockets directly from the kernel via `/proc/net`, checks host firewall rules, inspects Docker port mappings, and lists findings with specific fix instructions. When findings exist, it exits with status code 1, making it suitable for CI checks and server audits.

## Install

Install with Go (version 1.27 or later):

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

Build and run `exposecheck`:

```bash
$ ./exposecheck
Listeners
  public
    tcp  172.17.0.1:53
    tcp  172.18.0.1:53
    tcp  172.19.0.1:53
    tcp  172.20.0.1:53
    ... (trimmed 44 listeners) ...
    tcp  0.0.0.0:6333
    tcp  [::]:6333
    tcp  0.0.0.0:6334
    tcp  [::]:6334
    tcp  [::]:8000                gohttpserver (pid 1932)
  local
    tcp  127.0.0.1:53
    tcp  127.0.0.53:53
    ... (trimmed 28 listeners) ...
    tcp  127.0.0.1:6379
    tcp  127.0.0.1:8123

Findings (4)
  [docker] tcp 0.0.0.0:6333: container demo-db publishes port 6333/tcp on all interfaces; Docker bypasses ufw
    fix: publish with -p 127.0.0.1:6333:6333, or filter in the DOCKER-USER chain
  [docker] tcp 0.0.0.0:6334: container demo-db publishes port 6334/tcp on all interfaces; Docker bypasses ufw
    fix: publish with -p 127.0.0.1:6334:6334, or filter in the DOCKER-USER chain
  [docker] tcp [::]:6333: container demo-db publishes port 6333/tcp on all interfaces; Docker bypasses ufw
    fix: publish with -p 127.0.0.1:6333:6333, or filter in the DOCKER-USER chain
  [docker] tcp [::]:6334: container demo-db publishes port 6334/tcp on all interfaces; Docker bypasses ufw
    fix: publish with -p 127.0.0.1:6334:6334, or filter in the DOCKER-USER chain

Notes
  process names need root: run with sudo to see them
  ufw: not root, skipped
  iptables: not root, skipped
  nft: not root, skipped

$ echo $?
1
```

*(Listener list above was trimmed for brevity.)*

### Filter public listeners

Run with `--only public` to omit local, tailnet, and bridge listeners from the report:

```bash
$ ./exposecheck --only public
Listeners
  public
    tcp  192.168.1.106:53
    tcp  [fe80::8563:dc16:5b50:af19]:53
    udp  192.168.1.106:53
    udp  [fe80::8563:dc16:5b50:af19]:53
    udp  0.0.0.0:67
    udp  [fe80::8563:dc16:5b50:af19]:546
    tcp  [::]:3389                gnome-remote-de (pid 3988)
    udp  0.0.0.0:5353
    udp  [::]:5353
    tcp  [::]:8000                gohttpserver (pid 1843)
    tcp  [::]:21115               hbbs (pid 1864)
    tcp  [::]:21116               hbbs (pid 1864)
    udp  [::]:21116               hbbs (pid 1864)
    tcp  [::]:21117               hbbr (pid 1862)
    tcp  [::]:21118               hbbs (pid 1864)
    tcp  [::]:21119               hbbr (pid 1862)
    udp  [::]:43687               hbbs (pid 1864)

No findings.

Notes
  process names need root: run with sudo to see them
  ufw: not root, skipped
  iptables: not root, skipped
  nft: not root, skipped

$ echo $?
0
```

### JSON output

Run with `--json` for machine-readable JSON output:

```bash
$ ./exposecheck --json
```

Combine `--only public` and `--json` to filter JSON output to public listeners:

```bash
$ ./exposecheck --only public --json
```

See [docs/exit-codes-and-json.md](docs/exit-codes-and-json.md) for JSON schema details, exit codes, and output examples.

### Version

Print the build version and exit:

```bash
$ ./exposecheck --version
v0.1.2-0.20261110022950-64cc544c8f33
```

## How it works

- **Socket tables:** Reads listening sockets from `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6`.
- **Process resolution:** Maps socket inode to PID and process name via `/proc/*/fd` symlinks and `/proc/<pid>/comm`.
- **Firewall inspection:** Queries `ufw status verbose`, `iptables -S`, and `nft list ruleset` for rules blocking incoming traffic on public ports.
- **Docker audit:** Runs `docker ps` to find containers publishing ports to all interfaces (`0.0.0.0` or `[::]`).

## Limits

- **Linux only:** Requires Linux `/proc` filesystems (`/proc/net/*` and `/proc/<pid>/fd/*`).
- **Own host only:** Audits the local host where the binary runs.
- **No remote scan:** Does not scan remote hosts or send network packets to probe ports.
- **No config file:** Takes only `--json`, `--only public`, and `--version`. No config file or exclusion rule file.
- **No auto-fix:** Reports actionable fix commands, but does not modify firewalls or restart containers.
- **Firewall parsing is simple:** Ignores source addresses and network interfaces. Hosts where the `INPUT` chain jumps to other chains (such as `ufw`) are noted and not evaluated.
- **Needs root:** Needs root privileges (e.g. `sudo`) to resolve process names of other users and to query firewall tools (`ufw`, `iptables`, `nft`).
- **Address classification:** Addresses on `docker0`, `br-*` and `virbr*` interfaces are class `bridge` and raise no findings. Every other non-loopback, non-tailnet address counts as public, including LAN addresses.

## License

MIT. See [LICENSE](LICENSE).
