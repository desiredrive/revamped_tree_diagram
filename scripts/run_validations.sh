#!/usr/bin/env bash
# Batch-runs every programming validation against edge-1.
# Each test re-logs in via certificate; expect ~10-20s per test.

set -u
export RADKIT_KEY_PASSWORD="${RADKIT_KEY_PASSWORD:-Mexico123!}"

HOST="edge-1-jalejand-cisco-com"
PY=".venv/bin/python -m programming.test_runner"

run() {
    echo
    echo "############################################################"
    echo "# $*"
    echo "############################################################"
    $PY "$@" || echo "(exit $?)"
}

run route-full-compare --hostname "$HOST" --prefix 172.19.2.2/31
run route-full-compare --hostname "$HOST" --prefix 172.19.2.6/31
run route-full-compare --hostname "$HOST" --prefix 172.19.252.0/31
run route-full-compare --hostname "$HOST" --prefix 172.19.1.68/32
run route-full-compare --hostname "$HOST" --prefix 0.0.0.0/0 --vrf Campus
run route-full-compare --hostname "$HOST" --prefix 172.19.10.0/24 --vrf Campus
run route-full-compare --hostname "$HOST" --prefix 172.19.10.10 --vrf Campus

run lispl3if-compare --hostname "$HOST" --iid 4097
run lispl3if-compare --hostname "$HOST" --iid 4099
run lispl3if-compare --hostname "$HOST" --iid 4100
run lispl3if-compare --hostname "$HOST" --iid 4101

run lispadj-compare --hostname "$HOST" --rloc 172.19.1.64 --iid 4099
run lispadj-compare --hostname "$HOST" --rloc 172.19.1.64 --iid 4100

run compare --hostname "$HOST" --mac AAAA.BBBB.DDDD --vlan 1021
