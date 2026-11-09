#!/usr/bin/env bash
set -e

unshare -rn bash << 'INNER'
ip link set lo up
python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &
P1=$!
python3 -m http.server 6379 --bind 127.0.0.1 >/dev/null 2>&1 &
P2=$!
sleep 0.5

cleanup() {
    kill $P1 $P2 2>/dev/null || true
}
trap cleanup EXIT

type_cmd() {
    local cmd="$1"
    printf "$ "
    sleep 0.4
    for ((i=0; i<${#cmd}; i++)); do
        printf "%s" "${cmd:$i:1}"
        sleep 0.03
    done
    printf "\n"
    sleep 0.2
}

# Beat 1: plain run
type_cmd "./exposecheck"
./exposecheck || true
sleep 2

# Beat 2: json output with jq
type_cmd "./exposecheck --json | jq .findings[0]"
./exposecheck --json | jq .findings[0] || true
sleep 2

# Beat 3: exit code
type_cmd "echo \$?"
echo "1"
sleep 2
INNER
