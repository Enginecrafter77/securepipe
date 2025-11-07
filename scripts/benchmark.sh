#!/bin/sh

exe=../target/debug/securepipe

cat /dev/zero | pv | ${exe} | ${exe} -d >/dev/null
