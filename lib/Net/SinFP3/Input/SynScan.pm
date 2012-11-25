#
# $Id: SynScan.pm 2194 2012-11-13 20:55:10Z gomor $
#
package Net::SinFP3::Input::SynScan;
use strict;
use warnings;

use base qw(Net::SinFP3::Input);
our @AS = qw(
   ip
   port
   hostname
   fingerprint
   _eth
   _subnet
);
our @AA = qw(
   _ipList
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);
__PACKAGE__->cgBuildAccessorsArray (\@AA);

use Net::SinFP3::Next::IpPort;

use POSIX ":sys_wait_h";
use Net::Write::Fast;
use Net::Frame::Dump::Online2;
use Net::Frame::Simple;

sub give {
   return [
      'Net::SinFP3::Next::IpPort',
      'Net::SinFP3::Next::Frame',
   ];
}

sub new {
   my $self = shift->SUPER::new(
      hostname    => 'unknown',
      fingerprint => 0,
      nextList    => [],
      port        =>
   '1-1024,1025-1027,1029-1033,1040,1050,1058,1059,1067,1068,1076,1080,1083,'.
   '1084,1103,1109,1110,1112,1127,1139,1155,1178,1212,1214,1220,1222,1234,'.
   '1241,1248,1337,1346-1381,1383-1552,1600,1650-1652,1661-1672,1680,1720,'.
   '1723,1755,1761-1764,1827,1900,1935,1984,1986-2028,2030,2032-2035,2038,'.
   '2040-2049,2053,2064,2065,2067,2068,2105,2106,2108,2111,2112,2120,2121,'.
   '2201,2232,2241,2301,2307,2401,2430-2433,2500,2501,2564,2600-2605,2627,'.
   '2628,2638,2766,2784,2809,2903,2998,3000,3001,3005,3006,3049,3052,3064,'.
   '3086,3128,3141,3264,3268,3269,3292,3306,3333,3372,3389,3421,3455,3456,'.
   '3457,3462,3531,3632,3689,3900,3984,3985,3986,3999,4000,4008,4045,4132,'.
   '4133,4144,4224,4321,4333,4343,4444,4480,4500,4557,4559,4660,4672,4899,'.
   '4987,4998,5000,5001-5003,5010,5011,5050,5100-5102,5145,5190-5193,5232,'.
   '5236,5300-5305,5308,5400,5405,5490,5432,5510,5520,5530,5540,5550,5555,'.
   '5631,5632,5680,5713-5717,5800-5803,5900-5903,5977-5979,5997-6009,6017,'.
   '6050,6101,6103,6105,6106,6110-6112,6141,6142,6143,6144,6145-6148,6346,'.
   '6400,6401,6543,6544,6547,6548,6502,6558,6588,6666-6668,6969,6699,'.
   '7000-7010,7070,7100,7200,7201,7273,7326,7464,7597,8000-8082,'.
   '8443,8888,8892,9090,9100,9111,9152,9535,9876,9991,9992,9999,'.
   '10000,10005,10082,10083,11371,12000,12345,12346,13701,13702,13705,13706,'.
   '13708-13722,13782,13783,15126,16959,17007,17300,18000,18181-18185,18187,'.
   '19150,20005,22273,22289,22305,22321,22370,26208,27000-27010,27374,27665,'.
   '31337,32770-32780,32786,32787,38037,38292,43188,44334,44442,44443,47557,'.
   '49400,54320,61439-61441,65301',
      _ipList => [],
      @_,
   );

   my $global = $self->global;
   my $log    = $global->log;

   if (!defined($self->ip)) {
      $log->fatal("You must provide ip attribute");
   }

   # We want to SynScan a subnet
   if ($self->ip =~ /^[0-9\/\-,\.]+$/) {
      if ($self->ip =~ /^[0-9\.]+\/[0-9]+$/) {
         $self->_subnet($self->ip);
      }
      my $list = $global->expandSubnet(subnet => $self->ip);
      $self->_ipList($list);
   }
   # We want a single target
   else {
      # We keep the provided hostname (or IP) here
      $self->hostname($self->ip);
      if ($global->dnsResolve) {
         my $ip = $global->getHostAddr(host => $self->ip) or return;
         $self->ip($ip);
      }
   }

   return $self;
}

sub _addToResult {
   my $self = shift;
   my ($f) = @_;

   my $global = $self->global;

   if ($self->fingerprint) {
      return Net::SinFP3::Next::Frame->new(
         global => $global,
         frame  => $f,
      );
   }
   else {
      my $eth = $f->ref->{ETH};
      my $ip  = $f->ref->{IPv4} || $f->ref->{IPv6};
      my $tcp = $f->ref->{TCP};

      my $res;
      if ($ip && $tcp) {
         $res = Net::SinFP3::Next::IpPort->new(
            global   => $global,
            ip       => $ip->src,
            port     => $tcp->src,
            hostname => $self->hostname,
         ) or return;
         if ($eth) {
            $res->mac($eth->src);
         }
         return $res;
      }
   }

   return;
}

sub init {
   my $self = shift->SUPER::init(@_) or return;

   my $global = $self->global;
   my $log    = $global->log;

   my $portList = $global->expandPorts(ports => $self->port);
   my @ipList   = $self->_ipList;

   # Prepare Dump object
   my $filter;
   if (@ipList > 1) {
      if (!$global->ipv6) {
         $filter = '((tcp and dst host '.$global->ip.') or ('.
                   'icmp and dst host '.$global->ip.'))';
      }
      else {
         $filter = '((tcp and dst host '.$global->ip6.' and src host '.
                   $self->ip.') or (icmp6 and dst host '.$global->ip6.'))';
      }
   }
   else {
      if (!$global->ipv6) {
         $filter = '((tcp and dst host '.$global->ip.' and src host '.
                   $self->ip.') or (icmp and dst host '.$global->ip.'))';
      }
      else {
         $filter = '((tcp and dst host '.$global->ip6.' and src host '.
                   $self->ip.') or (icmp6 and dst host '.$global->ip6.'))';
      }
   }
   if ($self->_subnet) {
       $filter .= ' and src net '.$self->_subnet;
   }
   my $oDump = $global->getDumpOnline(
      filter => $filter,
   ) or return;
   $oDump->start or return;

   # Main SYN scan loop
   my %ports    = map { $_ => 1 } @$portList;
   my @send     = @$portList;
   my @targets  = ();
   if (@ipList > 1) {
      @targets = @ipList;
   }
   else {
      @targets  = ( $self->ip );
   }
   my $nReq     = scalar(@send);
   my $nTargets = scalar(@targets);
   my $retry    = $global->retry;
   my $pps      = $global->pps;

   my $ipv6 = $global->ipv6;
   my $ip   = $global->ip;
   my $ip6  = $global->ip6;

   defined(my $pid = fork()) or $log->fatal("Can't fork() [$!]\n");
   if (! $pid) { # Son
      $log->debug("run send()");
      my $r = Net::Write::Fast::l4_send_tcp_syn_multi(
         $ipv6 ? $ip6 : $ip,
         \@targets,
         \@send,
         $pps,
         $retry,
         $ipv6,
      );
      if ($r == 0) {
         $log->fatal(Net::Write::Fast::nwf_geterror());
      }
      $log->debug("stop send()");
      exit(0);
   }
   # Parent
   #print "forked process [$pid]\n";
   my $nRep = 0;
   my %skip = ();
   while (! $oDump->timeout) {
      if (my $f = $oDump->next) {
         my $s = Net::Frame::Simple->newFromDump($f);
         if ($s->ref->{TCP}) {
            my $ip  = $ipv6 ? $s->ref->{IPv6} : $s->ref->{IPv4};
            my $tcp = $s->ref->{TCP};
            # Skip ports which already had a reply
            if ($skip{$ip->src}{$tcp->src}) {
               next;
            }
            if ($tcp->flags == 0x12) { # SYN+ACK
               my $res = $self->_addToResult($s) or next;
               my @old = $self->nextList;
               $self->nextList([ @old, $res ]);
               $log->verbose("Found ".$res->print);
               $skip{$ip->src}{$tcp->src}++;
            }
            elsif ($tcp->flags == 0x14) { # RST+ACK
               $skip{$ip->src}{$tcp->src}++;
            }
         }
         $nRep++;
      }
      if ($oDump->timeout) {
         $log->debug("Timeout occured");
         # If $pid has exited and a timeout has occured
         # waitpid returns 0 if process is running, -1 if stopped, and $pid at
         # first waitpid invocation since process exited.
         my $r = waitpid($pid, WNOHANG);
         last if $r != -1 && $r != 0;
         $log->debug("Timeout occured, but SYN send not finished");
         $oDump->timeoutReset;
      }
   }

   # Cleanup before end of init()
   $oDump->stop;

   return 1;
}

sub run {
   my $self = shift->SUPER::run(@_) or return;

   my @nextList = $self->nextList;
   my $next     = shift @nextList;
   $self->nextList(\@nextList);

   return $next;
}

1;

__END__

=head1 NAME

Net::SinFP3::Input::SynScan - TCP SYN scanning input method

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2011-2012, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
