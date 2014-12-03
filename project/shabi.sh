#!/bin/bash

make

sudo rmmod sniffer_mod

sudo insmod ./sniffer_mod.ko


