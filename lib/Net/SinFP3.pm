#
# $Id: SinFP3.pm 2188 2012-11-08 16:20:47Z gomor $
#
package Net::SinFP3;
use strict;
use warnings;

our $VERSION = '1.02';

use base qw(Class::Gomor::Array);
our @AS = qw(
   global
);
our @AA = qw(
   db
   mode
   search
   input
   output
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);
__PACKAGE__->cgBuildAccessorsArray (\@AA);

our %EXPORT_TAGS = (
   matchType => [qw(
      NS_MATCH_TYPE_S1S2S3
      NS_MATCH_TYPE_S1S2
      NS_MATCH_TYPE_S2
   )],
   matchMask => [qw(
      NS_MATCH_MASK_HEURISTIC0
      NS_MATCH_MASK_HEURISTIC1
      NS_MATCH_MASK_HEURISTIC2
   )],
);

our @EXPORT_OK = (
   @{$EXPORT_TAGS{matchType}},
   @{$EXPORT_TAGS{matchMask}},
);

use constant NS_MATCH_TYPE_S1S2S3 => 'S1S2S3';
use constant NS_MATCH_TYPE_S1S2   => 'S1S2';
use constant NS_MATCH_TYPE_S2     => 'S2';

use constant NS_MATCH_MASK_HEURISTIC0 => 'BH0FH0WH0OH0MH0SH0LH0';
use constant NS_MATCH_MASK_HEURISTIC1 => 'BH1FH1WH1OH1MH1SH1LH1';
use constant NS_MATCH_MASK_HEURISTIC2 => 'BH2FH2WH2OH2MH2SH2LH2';

use Net::SinFP3::Worker qw(:consts);

sub new {
   my $class = shift;
   my %param = @_;

   # Sets unbuffered STDOUT
   $|++;

   if (!exists($param{output})
   ||  !exists($param{input})
   ||  !exists($param{mode})
   ||  !exists($param{search})
   ||  !exists($param{global})
   ||  !exists($param{db})) {
      die("[-] ".__PACKAGE__.": You must provide all of the following ".
          "attributes: output, input, mode, search, db, global\n");
   }

   my $self = $class->SUPER::new(
      db     => [],
      input  => [],
      mode   => [],
      search => [],
      output => [],
      @_,
   );

   my $log = $self->global->log;

   {
      no strict 'vars';
      for my $var ('output', 'input', 'db', 'mode', 'search') {
         my $idx = '$__'.$var;
         my $ref = ref($self->[eval($idx)]);
         if ($ref !~ /^ARRAY$/) {
            $log->fatal("$var attribute must be an ARRAYREF and it is [$ref]");
         }
      }
   }

   return $self;
}

sub _do {
   my $self = shift;

   my $global = $self->global;
   my $log    = $global->log;
   my $next   = $global->next;

   my @db     = $self->db;
   my @mode   = $self->mode;
   my @search = $self->search;
   my @output = $self->output;

   $log->debug("DB     module list: [@db]");
   $log->debug("Mode   module list: [@mode]");
   $log->debug("Search module list: [@search]");
   $log->debug("Output module list: [@output]");

   for my $db (@db) {
      $log->info("Starting of DB [".ref($db)."]");
      $global->db($db);
      $db->init or $log->fatal("Unable to init [".ref($db)."] module");
      $db->run or next;
      $log->info("Running of DB [".ref($db)."]: Done");
      for my $mode (@mode) {
         $global->mode($mode);

         $log->verbose(
            "Running with Next: ".$next->print." with type [".ref($next)."]"
         );
         $log->info("Starting of Mode [".ref($mode)."]");
         $mode->init or $log->fatal("Unable to init [".ref($mode)."] module");
         $mode->run or next;
         $log->info("Running of Mode [".ref($mode)."]: Done");

         for my $search (@search) {
            $global->search($search);

            $log->info("Starting of Search [".ref($search)."]");
            $search->init or $log->fatal("Unable to init [".ref($search).
                                         "] module");
            my $result = $search->run or next;
            $global->result($result);
            $log->info("Running of Search [".ref($search)."]: Done");

            $mode->postSearch;

            for my $output (@output) {
               $global->output($output);

               $log->info("Starting of Output [".ref($output)."]");
               $output->init or $log->fatal("Unable to init [".ref($output).
                                            "] module");
               $output->run or next;
               $output->post;
               $log->info("Running of Output [".ref($output)."]: Done");
            }
            $search->post;
         }
         $mode->post;
      }
      $db->post;
   }

   return 1;
}

sub _getWorkerModel {
   my $self = shift;

   my $global = $self->global;
   my $log    = $global->log;

   my $model;
   if ($global->worker =~ /fork/i) {
      eval "use Net::SinFP3::Worker::Fork";
      if ($@) {
         chomp($@);
         $log->fatal("Unable to use worker model Fork: error [$@]");
      }
      $model = 'Net::SinFP3::Worker::Fork';
   }
   elsif ($global->worker =~ /thread/i) {
      eval "use Net::SinFP3::Worker::Thread";
      if ($@) {
         chomp($@);
         $log->fatal("Unable to use worker model Thread: error [$@]");
      }
      $model = 'Net::SinFP3::Worker::Thread';
   }

   return $model;
}

sub run {
   my $self = shift;

   my $global = $self->global;
   my $log    = $global->log;
   my @input  = $self->input;

   # Beware, recursive loop
   $log->global($global);

   my $worker = $self->_getWorkerModel->new(
      global => $global,
   );

   my $job = 0;
   for my $input (@input) {
      $log->info("Starting of Input [".ref($input)."]");
      $input->init or $log->fatal("Unable to init [".ref($input)."] module");

      $global->input($input);

      while (my $next = $input->run) {
         last unless defined($next);

         my @next = (ref($next) =~ /^ARRAY$/) ? @$next : ( $next );
         for my $next (@next) {
            $global->job(++$job);
            $global->next($next);

            $worker->init(
               callback => sub {
                  $self->_do;
               },
            ) or $log->fatal("Unable to init [".ref($worker)."] module");

            $log->info("Starting of job with Next ".$next->print);

            # We are just before fork()ing or thread()ing.
            # Now, all data will be copied to the new process.
            my $r = $worker->run;
            next if $r == NS_WORKER_SUCCESS;

            $log->info("Running of job with Next [".$next->print."]: Done");

            $worker->post;
         }
      }
      $global->job(0);
      $input->post;
      $log->info("Running of Input [".ref($input)."]: Done");
   }

   $worker->clean;

   return 1;
}

1;

__END__

=head1 NAME

Net::SinFP3 - more than OS fingerprinting unification

=head1 SYNOPSIS

   use Net::SinFP3;

   my $sinfp = Net::SinFP3->new(
      global => $global,
      input  => [ $input  ],
      db     => [ $db     ],
      mode   => [ $mode   ],
      search => [ $search ],
      output => [ $output ],
   );

   $sinfp->run;

=head1 DESCRIPTION

This is the main starting point to run B<Net::SinFP3> plugins. It includes a main run loop, which will launch various plugins in this specific order:

   input > next > db > mode > search > output

This loop is ran against B<Net::SinFP3::Next> objects as returned by B<Net::SinFP3::Input> objects.

These attributes are passed as arrayref, so you will be able to launch multiple plugin of different types successively. Plugins have a base class which is one of:

  input:  Net::SinFP3::Input
  db:     Net::SinFP3::DB
  mode:   Net::SinFP3::Mode
  search: Net::SinFP3::Search
  output: Net::SinFP3::Output

The global attribute is an object which is passed to all modules. It contains global variables, and pointers to currently running plugins. See B<Net::SinFP3::Global>.

=head1 ATTRIBUTES

=over 4

=item B<global> (B<Net::SinFP3::Global>)

The global object containing global parameters and pointers to currently executing plugins.

=item B<input> ([ B<Net::SinFP3::Input>, ... ])

Arrayref of B<Net::SinFP3::Input> objects.

=item B<db> ([ B<Net::SinFP3::DB>, ... ])

Arrayref of B<Net::SinFP3::DB> objects.

=item B<mode> ([ B<Net::SinFP3::Mode>, ... ])

Arrayref of B<Net::SinFP3::Mode> objects.

=item B<search> ([ B<Net::SinFP3::Search>, ... ])

Arrayref of B<Net::SinFP3::Search> objects.

=item B<output> ([ B<Net::SinFP3::Output>, ... ])

Arrayref of B<Net::SinFP3::Output> objects.

=back

=head1 METHODS

=over 4

=item B<new> (%h)

Object constructor. You must give it the following attributes: global, input, db, mode, search, output.

=item B<run> ()

To use when you are ready to launch the main loop.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2011-2012, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
