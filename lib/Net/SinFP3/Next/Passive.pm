#
# $Id: Passive.pm 2234 2014-04-08 13:05:14Z gomor $
#
package Net::SinFP3::Next::Passive;
use strict;
use warnings;

use base qw(Net::SinFP3::Next);
our @AS = qw(
   sp
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

use Net::SinFP3::Ext::SP;

sub new {
   my $self = shift->SUPER::new(
      sp => Net::SinFP3::Ext::SP->new,
      @_,
   );

   return $self;
}

sub print {
   my $self = shift;

   my $buf = 'SP: '.$self->sp->print;

   return $buf;
}

1;

__END__

=head1 NAME

Net::SinFP3::Next::Passive - object describing a SinFP3 passive signature

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 ATTRIBUTES

=head1 METHODS

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2011-2014, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
