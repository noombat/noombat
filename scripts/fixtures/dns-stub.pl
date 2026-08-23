#!/usr/bin/perl
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# A DNS server that answers TXT queries from a fixed table and nothing
# else. It exists so DKIM verification can be tested: a verifier needs
# the signing domain's public key from DNS, and a test relay has no
# domain and no zone to publish one in.
#
# Anything it does not know is answered SERVFAIL rather than NXDOMAIN,
# deliberately. NXDOMAIN is an authoritative "no", and a resolver
# accepts it and stops; SERVFAIL makes it try the next nameserver, so
# this can be listed first in resolv.conf ahead of the real one and only
# intercepts the names it was given.
#
# Perl because the relay image has perl and no python.
#
# Usage:
#   dns-stub.pl --record NAME=VALUE [--record ...] [--bind ADDR] [--port N]
#
#   --record noombat._domainkey.chat.localhost=v=DKIM1; k=rsa; p=MIIB...
#
# Prints one line per query, so a test can show what was asked for.

use strict;
use warnings;
use IO::Socket::INET;

my %records;
my $bind = "127.0.0.1";
my $port = 53;

while (@ARGV) {
    my $flag = shift @ARGV;
    if ($flag eq "--record") {
        my $pair = shift @ARGV // die "--record needs NAME=VALUE\n";
        my ($name, $value) = split /=/, $pair, 2;
        die "--record needs NAME=VALUE\n" unless defined $value;
        $records{lc $name} = $value;
    } elsif ($flag eq "--bind") {
        $bind = shift @ARGV;
    } elsif ($flag eq "--port") {
        $port = shift @ARGV;
    } else {
        die "unknown option: $flag\n";
    }
}
die "no --record given, so this would answer nothing\n" unless %records;

my $sock = IO::Socket::INET->new(
    LocalAddr => $bind,
    LocalPort => $port,
    Proto     => "udp",
) or die "bind $bind:$port: $!\n";

$| = 1;
print "dns-stub: listening on $bind:$port with " . scalar(keys %records) . " record(s)\n";

# Read a DNS name from $packet at $offset. Returns (name, next offset).
# Compression pointers are not followed: a question section never uses
# them, and this only ever reads questions.
sub read_name {
    my ($packet, $offset) = @_;
    my @labels;
    while (1) {
        my $len = ord substr($packet, $offset, 1);
        $offset += 1;
        last if $len == 0;
        return (undef, $offset) if $len > 63;
        push @labels, substr($packet, $offset, $len);
        $offset += $len;
    }
    return (join(".", @labels), $offset);
}

# A TXT rdata field: the string in chunks of at most 255 bytes, each
# preceded by its length.
sub txt_rdata {
    my ($value) = @_;
    my $rdata = "";
    for (my $i = 0; $i < length($value); $i += 255) {
        my $chunk = substr($value, $i, 255);
        $rdata .= chr(length $chunk) . $chunk;
    }
    return $rdata;
}

while (1) {
    my $query;
    next unless defined $sock->recv($query, 4096);
    next if length($query) < 12;

    my ($id, $flags, $qdcount) = unpack("n n n", $query);
    next unless $qdcount >= 1;

    my ($name, $offset) = read_name($query, 12);
    next unless defined $name;
    my ($qtype, $qclass) = unpack("n n", substr($query, $offset, 4));
    $offset += 4;
    my $question = substr($query, 12, $offset - 12);

    my $key = lc $name;
    my $value = ($qtype == 16) ? $records{$key} : undef;

    if (defined $value) {
        print "dns-stub: TXT $name -> answered\n";
        # QR, AA, and the recursion-desired bit echoed back.
        my $header = pack("n n n n n n", $id, 0x8400 | ($flags & 0x0100), 1, 1, 0, 0);
        my $rdata = txt_rdata($value);
        # 0xC00C is a pointer to offset 12, where the question's name
        # begins, which is how every answer names it.
        my $answer = pack("n n n N n", 0xC00C, 16, 1, 60, length $rdata) . $rdata;
        $sock->send($header . $question . $answer);
    } else {
        my $what = $qtype == 16 ? "TXT" : "type $qtype";
        print "dns-stub: $what $name -> SERVFAIL, not ours\n";
        my $header = pack("n n n n n n", $id, 0x8402 | ($flags & 0x0100), 1, 0, 0, 0);
        $sock->send($header . $question);
    }
}
