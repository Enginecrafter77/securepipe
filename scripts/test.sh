#!/bin/sh

script_dir=$(dirname $(realpath $0))

src="/var/log/pacman.log"
exe="${script_dir}/../target/debug/securepipe"

cat "${src}" | ${exe} &
writer=$!

${exe} -d localhost >/dev/null 2>dec.log
dec_ec=$?

wait ${writer}
enc_ec=$?

rc=0
if [ ! "${dec_ec}" = "0" ]
then
    echo "Decryption endpoint exited abnormally (${dec_ec}). See dec.log for more details." >&2
    rc=$((rc+1))
fi
if [ ! "${enc_ec}" = "0" ]
then
    echo "Encryption endpoint exited abnormally (${enc_ec}). See enc.log for more details." >&2
    rc=$((rc+2))
fi
exit ${rc}
