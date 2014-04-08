#
# $Id: Null.pm 2234 2014-04-08 13:05:14Z gomor $
#
package Net::SinFP3::Mode::Null;
use strict;
use warnings;

use base qw(Net::SinFP3::Mode);
__PACKAGE__->cgBuildIndices;

1;

__END__

=head1 NAME

Net::SinFP3::Mode::Null - turn off Mode plugin

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2011-2014, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
