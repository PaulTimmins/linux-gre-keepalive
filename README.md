# linux-gre-keepalive
Userspace daemon in perl to handle Cisco GRE keepalives. Works in Linux, should work in any *nix derivative

Requires Net::Pcap, NetPacket::IP, and Proc::Daemon

(all 3 have stable debian perl packages in the standard repositories)

Usage:

sysctl -w net.ipv4.ip_forward=1

sysctl -w net.ipv6.conf.all.forwarding=1

ip tunnel add mytunnel mode gre remote x.x.x.x local y.y.y.y ttl 255 pmtudisc

ip link set mytunnel up

./gre-keepalive.pl mytunnel


This daemon does not initiate keepalive packets, but does look for ones sent by the originating system and redirects them as a standard Cisco router would, thus causing the GRE tunnel to go up/up, and causing it to go up/down if connectivity is lost. 
