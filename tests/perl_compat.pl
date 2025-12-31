#!/usr/bin/env perl
#
# Perl runtime compatibility test for safe-shell sandbox.
#
# Run under sandbox: safe-shell 'perl /workspace/tests/perl_compat.pl'
#

use strict;
use warnings;
use Socket;
use POSIX qw(setuid);
use File::Temp qw(tempfile tempdir);
use IO::Socket::INET;

print "=" x 75, "\n";
print "PERL RUNTIME SANDBOX COMPATIBILITY TEST\n";
print "=" x 75, "\n";

my @results;

sub test {
    my ($category, $name, $func) = @_;
    eval {
        my $result = $func->();
        my $display = defined $result ? substr("$result", 0, 25) : "undef";
        push @results, [$category, $name, "PASS", $display];
    };
    if ($@) {
        my $err = ref($@) ? ref($@) : $@;
        $err =~ s/\n.*//s;
        $err = substr($err, 0, 25);
        push @results, [$category, $name, "BLOCKED", $err];
    }
}

# FILESYSTEM
test("Filesystem", "Read files", sub {
    open my $fh, '<', '/etc/passwd' or die $!;
    my $line = <$fh>;
    close $fh;
    return substr($line, 0, 10);
});

test("Filesystem", "List directories", sub {
    opendir my $dh, '/usr' or die $!;
    my @entries = readdir($dh);
    closedir $dh;
    return scalar @entries;
});

test("Filesystem", "Write to /tmp", sub {
    open my $fh, '>', '/tmp/perl_test' or die $!;
    print $fh "x";
    close $fh;
    return 1;
});

test("Filesystem", "Write to /dev/shm", sub {
    open my $fh, '>', '/dev/shm/perl_test' or die $!;
    print $fh "x";
    close $fh;
    unlink '/dev/shm/perl_test';
    return 1;
});

test("Filesystem", "File::Temp tempfile", sub {
    my ($fh, $filename) = tempfile(DIR => $ENV{TMPDIR} || '/tmp');
    print $fh "test";
    close $fh;
    unlink $filename;
    return $filename;
});

test("Filesystem", "File::Temp tempdir", sub {
    my $dir = tempdir(DIR => $ENV{TMPDIR} || '/tmp', CLEANUP => 1);
    return $dir;
});

# NETWORK
test("Network", "TCP socket create", sub {
    socket(my $sock, PF_INET, SOCK_STREAM, 0) or die $!;
    close $sock;
    return "created";
});

test("Network", "TCP connect", sub {
    my $sock = IO::Socket::INET->new(
        PeerAddr => '8.8.8.8',
        PeerPort => 53,
        Proto    => 'tcp',
        Timeout  => 2
    ) or die $!;
    close $sock;
    return "connected";
});

test("Network", "UDP socket", sub {
    socket(my $sock, PF_INET, SOCK_DGRAM, 0) or die $!;
    close $sock;
    return "created";
});

test("Network", "Unix socket", sub {
    socket(my $sock, PF_UNIX, SOCK_STREAM, 0) or die $!;
    close $sock;
    return "created";
});

# PROCESSES
test("Process", "fork/exec", sub {
    my $output = `echo hello`;
    chomp $output;
    return $output;
});

test("Process", "system()", sub {
    my $ret = system("true");
    return $ret == 0 ? "success" : "failed";
});

test("Process", "kill self", sub {
    kill 0, $$;
    return "allowed";
});

test("Process", "kill pid 1", sub {
    my $ret = kill 0, 1;
    die "Operation not permitted" if $ret == 0;
    return "allowed";
});

test("Process", "setuid(0)", sub {
    setuid(0) or die $!;
    return "set";
});

# IPC
test("IPC", "pipe", sub {
    pipe(my $read, my $write) or die $!;
    print $write "test\n";
    close $write;
    my $data = <$read>;
    close $read;
    return $data;
});

test("IPC", "socketpair AF_UNIX", sub {
    # NOTE: socketpair(AF_UNIX) works even though socket(AF_UNIX) is blocked
    # This is because seccomp blocks socket() syscall but not socketpair()
    socketpair(my $a, my $b, AF_UNIX, SOCK_STREAM, 0) or die $!;
    print $a "test";
    close $a;
    my $msg = <$b>;
    close $b;
    return $msg;
});

# RESOURCES (via shell ulimit)
test("Resources", "read ulimit -u", sub {
    my $nproc = `ulimit -u`;
    chomp $nproc;
    return $nproc;
});

test("Resources", "raise ulimit -u", sub {
    my $ret = system("ulimit -u 9999 2>&1");
    die "failed" if $ret != 0;
    return "set";
});

# SIGNALS
test("Signals", "SIGALRM handler", sub {
    local $SIG{ALRM} = sub { };
    alarm(0);
    return "set";
});

test("Signals", "SIGCHLD handler", sub {
    local $SIG{CHLD} = 'IGNORE';
    return "set";
});

# Print results
print "\n";
my $current_cat = "";
for my $r (@results) {
    my ($cat, $name, $status, $details) = @$r;
    if ($cat ne $current_cat) {
        print "\n[$cat]\n";
        $current_cat = $cat;
    }
    my $symbol = $status eq "PASS" ? "+" : "-";
    printf "  %s %-25s %-10s %s\n", $symbol, $name, $status, $details;
}

my $passed = scalar grep { $_->[2] eq "PASS" } @results;
my $blocked = scalar grep { $_->[2] eq "BLOCKED" } @results;

print "\n";
print "=" x 75, "\n";
print "SUMMARY: $passed allowed, $blocked blocked\n";
print "=" x 75, "\n";

# Exit with error if unexpected results
# Expected: ~12 allowed, ~10 blocked
if ($passed < 10) {
    print "WARNING: Fewer features working than expected!\n";
    exit 1;
}
