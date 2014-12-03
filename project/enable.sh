#!/bin/bash

./sniffer_control --mode enable --dst_ip localhost --dst_port 4000

./sniffer_control --mode enable --src_ip fireless.cs.cornell.edu --src_port 80 --action capture

./tcp-proxy fireless.cs.cornell.edu 80 4000 
