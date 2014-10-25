#
# $Id: Worker.pm 2121 2012-04-14 10:22:46Z gomor $
#
package Net::SinFP3::Worker;
use strict;
use warnings;

use base qw(Class::Gomor::Array);
our @AS = qw(
   global
   callback
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

our %EXPORT_TAGS = (
   consts => [qw(
      NS_WORKER_SUCCESS
      NS_WORKER_FAIL
   )],
);

our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NS_WORKER_FAIL    => 0;
use constant NS_WORKER_SUCCESS => 1;

sub new {
   my $self = shift->SUPER::new(
      @_,
   );

   if (!defined($self->global)) {
      die("[-] ".__PACKAGE__.": You must provide a global attribute\n");
   }

   my $log = $self->global->log;

   my ($model) = caller();
   $log->verbose("Will use [$model] as worker model");

   return $self;
}

sub init {
   my $self = shift;
   my %h = @_;

   $self->callback($h{callback});

   return $self;
}

sub run {
   my $self = shift;
   return $self;
}

sub post {
   my $self = shift;
   return $self;
}

sub clean {
   my $self = shift;
   return $self;
}

1;

__END__

=head1 NAME

Net::SinFP3::Worker - base class for worker models

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
