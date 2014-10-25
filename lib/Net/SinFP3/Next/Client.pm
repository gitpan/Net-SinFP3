#
# $Id: Client.pm 2201 2012-11-18 12:59:19Z gomor $
#
package Net::SinFP3::Next::Client;
use strict;
use warnings;

use base qw(Net::SinFP3::Next);

our @AS = qw(
   peerhost
   peerport
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      @_,
   );

   return $self;
}

sub print {
   my $self = shift;

   my $buf = "[".$self->peerhost."]:".$self->peerport;

   return $buf;
}

1;

__END__

=head1 NAME

Net::SinFP3::Next::Client - a Next object to handle a network client

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2011-2012, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
