#!/bin/sh

script_dir=$(dirname $(realpath $0))

exe="${script_dir}/../target/release/securepipe"

${exe} -d >/dev/null &
dec_pid=$!

cat /dev/zero | pv | ${exe} localhost

wait ${dec_pid}
