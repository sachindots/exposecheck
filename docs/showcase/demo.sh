#!/usr/bin/env bash
set -e

TMPBIN=$(mktemp -d)
cat << 'MOCK' > "$TMPBIN/docker"
#!/bin/bash
if [ "$1" = "ps" ]; then
    printf "demo-db\t0.0.0.0:6333-6334->6333-6334/tcp, [::]:6333-6334->6333-6334/tcp\n"
    exit 0
fi
exec /usr/bin/docker "$@"
MOCK
chmod +x "$TMPBIN/docker"

cleanup() {
    rm -rf "$TMPBIN"
}
trap cleanup EXIT

export TMPBIN
unshare -rn bash << 'INNER'
export PATH="$TMPBIN:$PATH"
ip link set lo up
python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &
P1=$!
python3 -m http.server 6379 --bind 127.0.0.1 >/dev/null 2>&1 &
P2=$!
sleep 0.4

inner_cleanup() {
    kill $P1 $P2 2>/dev/null || true
}
trap inner_cleanup EXIT

type_cmd() {
    local cmd="$1"
    printf "$ "
    sleep 0.2
    for ((i=0; i<${#cmd}; i++)); do
        printf "%s" "${cmd:$i:1}"
        sleep 0.03
    done
    printf "\n"
    sleep 0.1
}

# Beat 1: First frame has output immediately (no blank screen)
printf "$ ./exposecheck\n"
./exposecheck || true
sleep 3

# Beat 2: JSON output with jq
type_cmd "./exposecheck --json | jq .findings[0]"
./exposecheck --json | jq .findings[0] || true
sleep 3

# Beat 3: Exit code
type_cmd 'echo $?'
echo "1"
sleep 3
INNER
