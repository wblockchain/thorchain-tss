#!/bin/bash
echo "nameserver 8.8.8.8">>/etc/resolv.conf
sleep 10
PRIVKEY="NWNiNzdkNGM2ZTk5M2IzM2MyMDg5YzI2MGE0NTM3MmQ4YjkzODUwYjJhZDFkODc4ODVkYjE4ZjA0OTA4ZWY1ZA=="
go build ./cmd/tss/main.go;echo $PRIVKEY | ./main -home /home/user/config -peer /ip4/3.104.66.61/tcp/6668/ipfs/16Uiu2HAm1xJMFrhg9pb4AnUhrUvjGkFTvNm1rvqnmAyUorrtXcS4
