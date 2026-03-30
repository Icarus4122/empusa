#!/usr/bin/env perl
use strict;
use warnings;

#
# perl-enum - Linux Enumeration (Perl)
#
# Runs common privesc enumeration commands.
# Useful when Python or Bash are restricted.
#
# Syntax check:  perl -c main.pl
# Run:           perl main.pl
#
#

my @commands = (
    ["Identity",       "id"],
    ["Hostname",       "hostname"],
    ["OS Info",        "cat /etc/os-release 2>/dev/null || cat /etc/issue"],
    ["Kernel",         "uname -a"],
    ["Users",          "cat /etc/passwd | grep -v nologin | grep -v false"],
    ["Groups",         "id"],
    ["Sudo Perms",     "sudo -l 2>/dev/null"],
    ["SUID Binaries",  "find / -perm -u=s -type f 2>/dev/null"],
    ["Capabilities",   "/usr/sbin/getcap -r / 2>/dev/null"],
    ["Writable Dirs",  "find / -writable -type d 2>/dev/null | head -20"],
    ["Cron Jobs",      "crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null"],
    ["Network",        "ip a 2>/dev/null || ifconfig"],
    ["Listening",      "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"],
    ["Processes",      "ps aux --sort=-%cpu | head -30"],
    ["Env Vars",       "env"],
    ["History",        "cat ~/.bash_history 2>/dev/null | tail -50"],
    ["Interesting",    "find / -name '*.conf' -o -name '*.bak' -o -name '*.old' -o -name '*.kdbx' 2>/dev/null | head -20"],
);

foreach my $item (@commands) {
    my ($label, $cmd) = @$item;
    print "\n" . "=" x 60 . "\n";
    print "  $label\n";
    print "=" x 60 . "\n";
    system($cmd);
}

print "\n[*] Enumeration complete.\n";
