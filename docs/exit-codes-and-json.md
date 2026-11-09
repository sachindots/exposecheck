# Exit codes and JSON output

`exposecheck` returns standard process exit codes and provides machine-readable JSON output via the `--json` flag.

## Exit codes

| Exit code | Meaning | Description |
|-----------|---------|-------------|
| `0` | Clean | The audit completed successfully and found zero security findings. All public listeners are blocked or safe. |
| `1` | Findings detected | The audit completed successfully and identified one or more unblocked public listeners or Docker port bypasses. |
| `2` | Error | Execution failed. Caused by invalid command-line flags (anything other than `--json`) or an internal failure while reading socket tables or network interfaces. |

In bash or shell scripts:

```bash
exposecheck
status=$?

if [ $status -eq 0 ]; then
  echo "Clean: no exposed ports"
elif [ $status -eq 1 ]; then
  echo "Warning: unblocked exposures detected"
  exit 1
else
  echo "Error running exposecheck"
  exit 2
fi
```

## JSON output (`--json`)

When invoked with `--json`, `exposecheck` prints a single JSON object to stdout.

```bash
exposecheck --json
```

### Top-level fields

The root object contains three arrays defined in `internal/report/report.go`:

| Field | Type | Description |
|-------|------|-------------|
| `listeners` | array of Listener | All listening network sockets found on the host. Always an array (never `null`). |
| `findings` | array of Finding | All identified exposure risks. Always an array (never `null`). |
| `notes` | array of Note (strings) | Informational messages detailing skipped tools or permission limits. Always an array (never `null`). |

### `listeners` items

Each object in `listeners` represents an open TCP or UDP socket, matching `sockets.Listener` from `internal/sockets/types.go`:

| Field | Type | Description |
|-------|------|-------------|
| `proto` | string | Transport protocol: `"tcp"` or `"udp"`. |
| `addr` | string | Bound IP address (e.g. `"0.0.0.0"`, `"127.0.0.1"`, `"::"`). |
| `port` | number | Port number (`1` to `65535`). |
| `inode` | number | Kernel socket inode number from `/proc/net/*`. |
| `class` | string | Address category: `"public"`, `"local"`, or `"tailnet"`. |
| `process` | object (optional) | Present when socket inode maps to a readable process in `/proc`. Omitted (`omitempty`) when unreadable or process exited. |

The `process` object matches `sockets.Process` from `internal/sockets/types.go`:

| Field | Type | Description |
|-------|------|-------------|
| `pid` | number | Process ID. |
| `command` | string | Command name read from `/proc/<pid>/comm`. |

#### Address classification (`class`)

- `"public"`: Unspecified addresses (`0.0.0.0`, `::`) or non-loopback addresses outside tailnet ranges (including Docker bridge interfaces).
- `"local"`: Loopback addresses (`127.0.0.0/8`, `::1`).
- `"tailnet"`: Tailscale addresses (`100.64.0.0/10`).

### `findings` items

Each object in `findings` describes an exposure risk, matching `sockets.Finding` from `internal/sockets/types.go`:

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Finding type: `"firewall"` or `"docker"`. |
| `proto` | string | Protocol: `"tcp"` or `"udp"`. |
| `addr` | string | Exposed IP address. |
| `port` | number | Exposed port number. |
| `reason` | string | Explanation of why this port is exposed. |
| `fix` | string | Recommended command or configuration to remediate the exposure. |

#### Finding kinds

- `"firewall"`: A public listener has no matching deny rule and no default drop policy in host firewall tools (`ufw`, `iptables`, `nft`).
- `"docker"`: A Docker container publishes ports on `0.0.0.0` or `[::]`. Docker injects iptables rules that bypass standard ufw rules.

### `notes` items

An array of strings reporting operational limits encountered during the audit. Examples:

- `"process names need root: run with sudo to see them"`: One or more `/proc/<pid>/fd/` directories could not be read due to permission limits.
- `"ufw: not root, skipped"`: ufw requires root to query rules.
- `"iptables: not root, skipped"`: iptables requires root to read rulesets.
- `"nft: not root, skipped"`: nftables requires root to list rulesets.
- `"docker: not installed, skipped"`: The `docker` CLI was not found in PATH.
- `"<tool>: INPUT jumps to other chains, not evaluated"`: The firewall delegates input traffic to external chains that exposecheck does not follow.

## Real JSON examples

### Output with findings

Real run of `./exposecheck --json` on host:

```bash
$ ./exposecheck --json
{
  "listeners": [
    {
      "proto": "tcp",
      "addr": "172.21.0.1",
      "port": 53,
      "inode": 38049,
      "class": "public"
    },
    ... (trimmed 79 listeners) ...
    {
      "proto": "tcp",
      "addr": "127.0.0.1",
      "port": 6379,
      "inode": 30421,
      "class": "local"
    }
  ],
  "findings": [
    {
      "kind": "docker",
      "proto": "tcp",
      "addr": "0.0.0.0",
      "port": 6333,
      "reason": "container demo-db publishes port 6333/tcp on all interfaces; Docker bypasses ufw",
      "fix": "publish with -p 127.0.0.1:6333:6333, or filter in the DOCKER-USER chain"
    },
    {
      "kind": "docker",
      "proto": "tcp",
      "addr": "0.0.0.0",
      "port": 6334,
      "reason": "container demo-db publishes port 6334/tcp on all interfaces; Docker bypasses ufw",
      "fix": "publish with -p 127.0.0.1:6334:6334, or filter in the DOCKER-USER chain"
    },
    {
      "kind": "docker",
      "proto": "tcp",
      "addr": "::",
      "port": 6333,
      "reason": "container demo-db publishes port 6333/tcp on all interfaces; Docker bypasses ufw",
      "fix": "publish with -p 127.0.0.1:6333:6333, or filter in the DOCKER-USER chain"
    },
    {
      "kind": "docker",
      "proto": "tcp",
      "addr": "::",
      "port": 6334,
      "reason": "container demo-db publishes port 6334/tcp on all interfaces; Docker bypasses ufw",
      "fix": "publish with -p 127.0.0.1:6334:6334, or filter in the DOCKER-USER chain"
    }
  ],
  "notes": [
    "process names need root: run with sudo to see them",
    "ufw: not root, skipped",
    "iptables: not root, skipped",
    "nft: not root, skipped"
  ]
}

$ echo $?
1
```

*(Listener list above was trimmed for brevity.)*

### Example output with zero findings

Example run of `./exposecheck --json` with zero findings:

```bash
$ ./exposecheck --json
{
  "listeners": [
    {
      "proto": "tcp",
      "addr": "127.0.0.1",
      "port": 5432,
      "inode": 3073699,
      "class": "local",
      "process": {
        "pid": 1284,
        "command": "postgres"
      }
    }
  ],
  "findings": [],
  "notes": [
    "ufw: not root, skipped",
    "docker: not installed, skipped"
  ]
}

$ echo $?
0
```
