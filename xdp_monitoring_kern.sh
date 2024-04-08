#!/bin/sh

clang -O2 -g -Wall -target bpf -c xdp_monitoring_kern.c -o xdp_monitoring_kern.o
sudo ip link set enp2s0f1 xdpgeneric off
sudo ip link set enp2s0f1 xdpgeneric obj xdp_monitoring_kern.o sec monitoring
