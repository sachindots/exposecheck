# Showcase: ExposeCheck

## Story Beats

1. **Beat 1: CLI report on listening sockets and findings**
   - Command: `./exposecheck`
   - Shows public listener (`0.0.0.0:8080`) alongside local listeners (`127.0.0.1:6379`).
   - Flags unblocked firewall exposure on port 8080 and Docker container port bypasses (`0.0.0.0:6333`, `0.0.0.0:6334`, `[::]:6333`, `[::]:6334`) with actionable remediation lines.
   - Explains unprivileged inspection notes.

2. **Beat 2: Machine-readable JSON output**
   - Command: `./exposecheck --json | jq .findings[0]`
   - Emits structured JSON findings suitable for automated parsing.

3. **Beat 3: Process exit status**
   - Command: `echo $?`
   - Returns exit code `1` when security findings exist, enabling CI and cron failure conditions.

## Asset Generation

- **Cast recording (`docs/showcase/demo.cast`):**
  - Command: `asciinema rec -c "bash docs/showcase/demo.sh" --cols 100 --rows 28 --overwrite docs/showcase/demo.cast`
- **GIF animation (`docs/showcase/demo.gif`):**
  - Command: `agg --theme monokai --font-size 16 docs/showcase/demo.cast docs/showcase/demo.gif`
  - Rendered size: 148 KB (well within 2 MB limit).
- **Plaintext output (`docs/showcase/demo-output.txt`):**
  - Captured directly from the compiled binary in an isolated demo namespace.
- **Showcase webpage (`docs/showcase/showcase.html`):**
  - Single standalone HTML page with responsive styling (desktop and mobile down to 390px), dark/light mode via `prefers-color-scheme`, zero external frameworks, and real capture snippets.

## Demo State Setup and Teardown

- **State setup:**
  - Started a test public listener: `python3 -m http.server 8080 --bind 0.0.0.0`
  - Started a test local listener: `python3 -m http.server 6379 --bind 127.0.0.1`
  - Isolated network namespace via `unshare -rn` with `lo` up to cleanly isolate listeners while checking Docker socket (`/var/run/docker.sock`).
- **Teardown:**
  - Trapped `EXIT` signal to terminate background Python processes (`kill $P1 $P2`).

## What Was Not Checked

- Live multi-node Tailscale mesh interfaces across multiple physical hosts.
- Proprietary firewall management frontends outside ufw, iptables, and nftables.
