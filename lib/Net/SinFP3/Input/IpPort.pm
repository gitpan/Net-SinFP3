#
# $Id: IpPort.pm 2155 2012-08-31 12:43:09Z gomor $
#
package Net::SinFP3::Input::IpPort;
use strict;
use warnings;

use base qw(Net::SinFP3::Input);
our @AS = qw(
   ip
   port
   hostname
   reverse
   mac
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

use Net::SinFP3::Next::IpPort;

sub give {
   return [
      'Net::SinFP3::Next::IpPort',
   ];
}

sub new {
   my $self = shift->SUPER::new(
      hostname => 'unknown',
      reverse  => 'unknown',
      mac      => '00:00:00:00:00:00',
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
      my $ip = $global->getHostAddr(host => $self->ip) or return;
      $self->ip($ip);
   }

   if ($global->dnsReverse) {
      $self->reverse($global->getAddrReverse(addr => $self->ip) || 'unknown');
   }

   return $self;
}

sub init {
   my $self = shift->SUPER::init(@_) or return;

   my $portList = $self->global->expandPorts(ports => $self->port);

   my $ip       = $self->ip;
   my $hostname = $self->hostname;
   my $reverse  = $self->reverse;
   my $mac      = $self->mac;
   my @nextList = ();
   for my $port (@$portList) {
      my $next = Net::SinFP3::Next::IpPort->new(
         global   => $self->global,
         ip       => $ip,
         port     => $port,
         hostname => $hostname,
         reverse  => $reverse,
         mac      => $mac,
      );
      push @nextList, $next;
   }

   $self->nextList(\@nextList);

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

Net::SinFP3::Input::IpPort - object describing a SinFP target

=head1 SYNOPSIS

   use Net::SinFP3::Input::IpPort;

=head1 DESCRIPTION

=head1 ATTRIBUTES

=over 4

=back

=head1 METHODS

=over 4

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2011-2012, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
