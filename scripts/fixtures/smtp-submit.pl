#!/usr/bin/perl
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Submit one message over SMTP and print the reply to the terminating
# dot. Used by scripts/check-relay-invariants.sh, from inside the relay
# container, which has perl but no mail client.
#
# Every reply is read before the next command is sent. Postfix's
# `smtpd_forbid_unauth_pipelining` closes the connection on a client
# that runs ahead, and the resulting "I can break rules, too" is easy to
# misread as a rejection of the message.
#
# Usage:
#   smtp-submit.pl --host H --port P --from F --to T --body KIND [--tag T]
#
#   --body encrypted   a PGP/MIME message the filter must accept
#   --body plain       a plaintext message the filter must refuse
#   --header-from A    put A in the From header instead of the envelope
#                      sender, so the two disagree
#   --message FILE     send FILE verbatim as the message, headers and
#                      all, so a signed message can be replayed
#
# Prints one line per step, the last being the reply to the message
# itself. Exits 0 when the conversation completed, whatever the relay
# decided, and 2 when it could not be completed at all.

use strict;
use warnings;
use IO::Socket::INET;

my %opt = (
    host => '127.0.0.1',
    port => 25,
    from => 'sender@chat.localhost',
    to   => 'destination@chat.localhost',
    body => 'encrypted',
    tag  => 'probe',
    # The From header, when it must disagree with the envelope sender.
    # Defaults to matching, which is the ordinary case.
    'header-from' => '',
    # Send an existing message verbatim instead of generating one, for
    # replaying something the relay itself signed.
    message => '',
);
while (@ARGV) {
    my $flag = shift @ARGV;
    $flag =~ s/^--//;
    die "unknown option: $flag\n" unless exists $opt{$flag};
    $opt{$flag} = shift @ARGV;
}

my $body = $opt{body} eq 'encrypted'
    ? join("\r\n",
        'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=bnd',
        '',
        '--bnd',
        'Content-Type: application/pgp-encrypted',
        '',
        'Version: 1',
        '',
        '--bnd',
        'Content-Type: application/octet-stream',
        '',
        '-----BEGIN PGP MESSAGE-----',
        'aGVsbG8gd29ybGQgY2lwaGVydGV4dA==',
        '-----END PGP MESSAGE-----',
        '',
        '--bnd--')
    : join("\r\n",
        'Content-Type: text/plain',
        '',
        'this message is not encrypted and the relay must refuse it');

my $sock = IO::Socket::INET->new(
    PeerAddr => $opt{host},
    PeerPort => $opt{port},
    Timeout  => 30,
) or do { print "connect failed: $!\n"; exit 2 };

sub read_reply {
    my $reply = '';
    while (my $line = <$sock>) {
        $reply .= $line;
        last if $line =~ /^\d{3} /;
    }
    $reply =~ s/\s+$//;
    return $reply;
}

sub step {
    my ($label, $command) = @_;
    print $sock "$command\r\n";
    my $reply = read_reply();
    my $last = (split /\n/, $reply)[-1] // '';
    printf "%-12s %s\n", $label, $last;
    exit 0 unless $last =~ /^[23]/;
    return $last;
}

my $greeting = read_reply();
printf "%-12s %s\n", 'greeting', (split /\n/, $greeting)[-1] // '';
exit 2 unless $greeting =~ /^220/;

step('ehlo', 'EHLO probe.invalid');
step('mail', "MAIL FROM:<$opt{from}>");
step('rcpt', "RCPT TO:<$opt{to}>");
step('data', 'DATA');
if ($opt{message} ne '') {
    open(my $fh, '<', $opt{message}) or do { print "cannot read $opt{message}: $!\n"; exit 2 };
    binmode $fh;
    local $/;
    my $raw = <$fh>;
    close $fh;
    # Normalise to CRLF and dot-stuff, or a body line beginning with a
    # dot would end the message early.
    $raw =~ s/\r\n/\n/g;
    for my $line (split /\n/, $raw, -1) {
        $line = ".$line" if $line =~ /^\./;
        print $sock "$line\r\n";
    }
} else {
    my $header_from = $opt{'header-from'} || $opt{from};
    print $sock "Subject: $opt{tag}\r\nFrom: <$header_from>\r\nTo: <$opt{to}>\r\n$body\r\n";
}

print $sock ".\r\n";
my $verdict = read_reply();
printf "%-12s %s\n", 'message', (split /\n/, $verdict)[-1] // '';

print $sock "QUIT\r\n";
exit 0;
