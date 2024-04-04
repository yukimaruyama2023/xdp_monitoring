#!/bin/sh

clang -O2 -g -Wall -target bpf -c xdp_udp_kern.c -o xdp_udp_kern.o
sudo ip link set test xdpgeneric off
sudo ip link set test xdpgeneric obj xdp_udp_kern.o sec udp_test
