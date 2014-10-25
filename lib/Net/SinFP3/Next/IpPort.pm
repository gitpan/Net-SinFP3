#
# $Id: IpPort.pm 2171 2012-09-12 11:45:38Z gomor $
#
package Net::SinFP3::Next::IpPort;
use strict;
use warnings;

use base qw(Net::SinFP3::Next);
our @AS = qw(
   ip
   mac
   port
   hostname
   reverse
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      ip       => '127.0.0.1',
      port     => 1,
      mac      => '00:00:00:00:00:00',
      hostname => 'unknown',
      reverse  => 'unknown',
      @_,
   );

   my $global = $self->global;
   my $log    = $global->log;

   if ($global->ipv6 && $self->mac =~ /00:00:00:00:00:00/) {
      my $mac = $global->lookupMac6(ipv6 => $self->ip);
      $self->mac($mac);
   }

   if ($global->dnsReverse) {
      my $reverse = $global->getAddrReverse(addr => $self->ip) || 'unknown';
      $self->reverse($reverse);
   }

   return $self;
}

sub print {
   my $self = shift;
   my $buf = "[".$self->ip."]:".$self->port;
   $buf .= " hostname[".$self->hostname."]";
   $buf .= " reverse[".$self->reverse."]";
   $buf .= " mac[".$self->mac."]";
   return $buf;
}

1;

__END__

=head1 NAME

Net::SinFP3::Next::IpPort - object describing the next target with IP and port

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 ATTRIBUTES

=head1 METHODS

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2011-2012, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
