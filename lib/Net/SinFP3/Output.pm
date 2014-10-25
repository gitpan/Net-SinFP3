#
# $Id: Output.pm 2121 2012-04-14 10:22:46Z gomor $
#
package Net::SinFP3::Output;
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
   # By default we take all objects
   if (@$take == 0) {
      return $self;
   }

   my @result = $self->global->result;
   for my $r (@result) {
      my $ref = ref($r);
      my $found;
      for my $t (@$take) {
         if ($ref =~ /^$t/) {
            $found++;
            last;
         }
      }
      if (! $found) {
         $log->error("Result type [$ref] not allowed with this plugin");
         return;
      }
   }

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

1;

__END__

=head1 NAME

Net::SinFP3::Output - base class for Output plugin objects

=head1 SYNOPSIS

   use base qw(Net::SinFP3::Output);

   # Your Output plugin code

=head1 DESCRIPTION

This is the base class for all B<Net::SinFP3::Output> plugins.

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

Return an array ref of allowed I<Result> object types.

=item B<init> ()

Do some initialization by writing this method.

=item B<run> ()

To use when you are ready to launch the main loop.

=item B<post> ()

Do some cleanup by writing this method. B<post> is run at the beginning of main B<Net::SinFP3> loop postlude. The exact order is:

   output->post > search->post > mode->post > db->post > input->post

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2011-2012, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
