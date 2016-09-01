#!/usr/bin/perl

use strict;
use warnings;

use Net::Pcap;
use NetPacket::IP;
use Proc::Daemon;
use Socket;
use constant DUMMY_ADDR  => scalar(sockaddr_in(0, inet_aton('1.0.0.0')));

Proc::Daemon::Init;

socket(RAW, AF_INET, SOCK_RAW, 255) || die $!;
setsockopt(RAW, 0, 1, 1);

my $dev = $ARGV[0];
my $err;
my $pcap = Net::Pcap::open_live($dev, 1024, 0, 0, \$err);

my $filter = "proto gre";
my $filter_t;
if (Net::Pcap::compile($pcap, \$filter_t, $filter, 0, 0) == -1) {
    die "Unable to compile filter string '$filter'\n";
}
Net::Pcap::setfilter($pcap, $filter_t);

Net::Pcap::loop($pcap, -1, \&process_packet, undef);

Net::Pcap::close($pcap);

sub process_packet {
    my ($user_data, $header, $packet) = @_;

    # Strip the "cooked capture" header.
    $packet = unpack("x16a*", $packet);

    my $pkt = NetPacket::IP->decode($packet);
    print "Sending $packet to $pkt->{'dest_ip'}\n";
    send(RAW, $packet, 0, DUMMY_ADDR) or die "Couldn't send packet: $!";
    print "Sent to $pkt->{'dest_ip'}\n";
}

