#!/usr/bin/env bash
set -e

cleanup() {
    docker rm -f demo-db >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker rm -f demo-db >/dev/null 2>&1 || true
docker run -d --rm --name demo-db -p 6333:80 nginx:alpine >/dev/null 2>&1

unshare -rn bash << 'INNER'
ip link set lo up
python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &
P1=$!
python3 -m http.server 6379 --bind 127.0.0.1 >/dev/null 2>&1 &
P2=$!
sleep 0.4

inner_cleanup() {
    kill $P1 $P2 2>/dev/null || true
}
trap inner_cleanup EXIT INT TERM

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
