#!/usr/bin/perl

use strict;
use warnings;

use Net::Pcap;
use NetPacket::IP;
use Proc::Daemon;
use Socket;
use constant DUMMY_ADDR  => scalar(sockaddr_in(0, inet_aton('1.0.0.0')));

Proc::Daemon::Init;

socket(my $socket, AF_INET, SOCK_RAW, 255) || die $!;
setsockopt($socket, 0, 1, 1);

my $dev = $ARGV[0];
my $err;
my $pcap = Net::Pcap::open_live($dev, 1024, 0, 0, \$err);

my $filter = "proto gre";
my $filter_t;
if (Net::Pcap::compile($pcap, \$filter_t, $filter, 1, 0) == -1) {
    die "Unable to compile filter string '$filter'\n";
}
Net::Pcap::setfilter($pcap, $filter_t);

Net::Pcap::loop($pcap, -1, \&process_packet, $socket);

Net::Pcap::close($pcap);

sub process_packet {
    my ($socket, $header, $packet) = @_;

    # Strip the "cooked capture" header.
    $packet = unpack("x16a*", $packet);

    my $pkt = NetPacket::IP->decode($packet);
    my $dest_ip = $pkt->{'dest_ip'};
    print "Sending $packet to $dest_ip\n";
    send($socket, $packet, 0, DUMMY_ADDR) or die "Couldn't send packet: $!";
    print "Sent to $dest_ip\n";
}

