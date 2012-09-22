#
# $Id: Connect.pm 2170 2012-09-11 15:49:55Z gomor $
#
package Net::SinFP3::Input::Connect;
use strict;
use warnings;

use base qw(Net::SinFP3::Input);
our @AS = qw(
   ip
   port
   hostname
   reverse
   data
   _dump
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

use Net::SinFP3::Next::MultiFrame;

sub give {
   return [
      'Net::SinFP3::Next::Frame',
   ];
}

sub new {
   my $self = shift->SUPER::new(
      hostname => 'unknown',
      reverse  => 'unknown',
      data     => "GET / HTTP/1.0\r\n\r\n",
      @_,
   );

   my $global = $self->global;
   my $log    = $global->log;

   if (!defined($self->ip)) {
      $log->fatal("You must provide ip attribute");
   }
   if (!defined($self->port)) {
      $log->fatal("You must provide port attribute");
   }

   my $port = $self->port;
   if ($port !~ /^[-,\d]+$/) {
      $log->fatal("Invalid port provided: [$port]");
   }

   # We keep the provided hostname (or IP) here
   $self->hostname($self->ip);
   if ($global->dnsResolve) {
      $self->ip($global->getHostAddr(host => $self->ip));
   }

   if ($global->dnsReverse) {
      $self->reverse($global->getAddrReverse(addr => $self->ip) || 'unknown');
   }

   return $self;
}

sub init {
   my $self = shift->SUPER::init(@_) or return;

   my $global = $self->global;
   my $log    = $global->log;

   my $me   = $global->ip;
   my $ip   = $self->ip;
   my $port = $self->port;

   # Capture TCP SYN and SYN|ACK between source and target
   my $filter = '';
   if ($global->ipv6) {
      $filter = "(tcp and host $ip and port $port)";
   }
   else {
      $filter = "(tcp and src host $ip and src port $port)".
                " or ".
                "(tcp and dst host $ip and dst port $port)".
                " and (tcp[tcpflags] == (tcp-syn|tcp-ack) or ".
                "      tcp[tcpflags] == (tcp-syn))";
   }

   my $oDump = $global->getDumpOnline(
      filter        => $filter,
      timeoutOnNext => 0,
   );
   $oDump->start;

   $self->_dump($oDump);

   return 1;
}

sub run {
   my $self = shift->SUPER::run(@_) or return;

   my $global = $self->global;
   my $log    = $global->log;

   $log->info("Connecting to [".$self->ip."]:".$self->port);

   my $s = $global->tcpConnect(ip => $self->ip, port => $self->port);
   print $s $self->data;
   close($s);

   $log->info("Success sending [".$self->data."]");

   my $oDump = $self->_dump;

   my @frames = ();
   while (my $h = $oDump->next) {
      my $frame = Net::Frame::Simple->newFromDump($h);

      # Due to some buggy pcap installs that miss ip6 filter
      if ($global->ipv6 && !$frame->ref->{IPv6}) {
         next;
      }

      push @frames, $frame;

      $self->last(1);
   }

   my $next = Net::SinFP3::Next::MultiFrame->new(
      global    => $global,
      frameList => \@frames,
   );

   return $next;
}

sub post {
   my $self = shift;
   $self->_dump->stop;
   $self->_dump(undef);
   return 1;
}

1;

__END__

=head1 NAME

Net::SinFP3::Input::Connect - methods used when in TCP connect active mode

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2011-2012, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
