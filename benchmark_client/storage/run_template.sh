#!/bin/bash
echo "nameserver 8.8.8.8">>/etc/resolv.conf
sleep 10
PRIVKEY="aaa"
go build ./cmd/tss/main.go;echo $PRIVKEY | ./main -home /home/user/config -peer /ip4/138.197.211.179/tcp/6668/ipfs/16Uiu2HAmHFyQF4of9Kiwqr5ADbbXxYsXqwP7QiEXcVeAMmZHEBMM

