#
# $Id: Active.pm 2234 2014-04-08 13:05:14Z gomor $
#
package Net::SinFP3::Next::Active;
use strict;
use warnings;

use base qw(Net::SinFP3::Next);
our @AS = qw(
   s1
   s2
   s3
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

use Net::SinFP3::Ext::S;

sub new {
   my $self = shift->SUPER::new(
      s1 => Net::SinFP3::Ext::S->new,
      s2 => Net::SinFP3::Ext::S->new,
      s3 => Net::SinFP3::Ext::S->new,
      @_,
   );

   return $self;
}

sub print {
   my $self = shift;

   my $buf = 'S1: '.$self->s1->print.' '.
             'S2: '.$self->s2->print.' '.
             'S3: '.$self->s3->print;

   return $buf;
}

1;

__END__

=head1 NAME

Net::SinFP3::Next::Active - object describing a SinFP3 active signature

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
