#
# $Id: Mode.pm 2234 2014-04-08 13:05:14Z gomor $
#
package Net::SinFP3::Mode;
use strict;
use warnings;

use base qw(Class::Gomor::Array);
our @AS = qw(
   global
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      @_,
   );

   if (!defined($self->global)) {
      die("[-] ".__PACKAGE__.": You must provide a global object\n");
   }

   return $self;
}

sub take {
   return [];
}

sub init {
   my $self = shift;

   my $log = $self->global->log;

   my $take = $self->take;
   # By default we take all Next objects
   if (@$take == 0) {
      return $self;
   }

   my $next = ref($self->global->next);
   for (@$take) {
      if (/^$next$/) {
         return $self;
      }
   }

   $log->error("Next type [$next] not allowed with this plugin");
   return;
}

sub run {
   my $self = shift;
   return $self;
}

sub post {
   my $self = shift;
   return $self;
}

sub postSearch {
   my $self = shift;
   return $self;
}

1;

__END__

=head1 NAME

Net::SinFP3::Mode - base class for Mode plugin objects

=head1 SYNOPSIS

   use base qw(Net::SinFP3::Mode);

   # Your Mode plugin code

=head1 DESCRIPTION

This is the base class for all B<Net::SinFP3::Mode> plugins.

=head1 ATTRIBUTES

=over 4

=item B<global> (B<Net::SinFP3::Global>)

The global object containing global parameters and pointers to currently executing plugins.

=back

=head1 METHODS

=over 4

=item B<new> (%hash)

Object constructor. You must give it the following attributes: B<global>.

=item B<take> ()

Return an array ref of allowed I<Next> object types.

=item B<init> ()

Do some initialization by writing this method.

=item B<run> ()

To use when you are ready to launch the main loop.

=item B<post> ()

Do some cleanup by writing this method. B<post> is run in the middle of main B<Net::SinFP3> loop postlude. The exact order is:

   output->post > search->post > mode->post > db->post > input->post

=item B<postSearch> ()

Execute this action right after a B<Net::SinFP3::Search> plugin B<run> method. This can be used, for instance, to modify search results.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2011-2014, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
