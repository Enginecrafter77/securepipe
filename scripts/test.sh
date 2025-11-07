#!/bin/sh

src="/var/log/pacman.log"
exe="../target/debug/securepipe"
pipe="pipe"

cat "${src}" | ${exe} > "${pipe}" 2>enc.log &
writer=$!

${exe} -d < "${pipe}" >/dev/null 2>dec.log
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
