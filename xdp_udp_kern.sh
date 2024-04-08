#!/bin/sh

clang -O2 -g -Wall -target bpf -c xdp_udp_kern.c -o xdp_udp_kern.o
sudo ip link set enp2s0f1 xdpgeneric off
sudo ip link set enp2s0f1 xdpgeneric obj xdp_udp_kern.o sec udp_test
