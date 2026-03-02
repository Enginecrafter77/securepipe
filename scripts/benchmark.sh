#!/bin/sh

script_dir=$(dirname $(realpath $0))

if [ ! -z "$1" ]
then
    exe="$1"
    shift 1
else
    exe="${script_dir}/../target/release/securepipe"
fi

${exe} -d $@ >/dev/null &
dec_pid=$!

cat /dev/zero | pv | ${exe} $@ localhost

wait ${dec_pid}
