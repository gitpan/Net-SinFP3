#
# $Id: Makefile.PL 2213 2012-12-02 10:14:41Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::SinFP3',
   VERSION_FROM  => 'lib/Net/SinFP3.pm',
   ABSTRACT_FROM => 'lib/Net/SinFP3.pm',
   LICENSE       => 'artistic',
   PREREQ_PM     => {
      Class::Gomor => 0,
      Data::Dumper => 0,
      DBD::SQLite => 0,
      DBI => 0,
      Digest::MD5 => 0,
      File::Glob => 0,
      FindBin => 0,
      Frontier::Client => 0,
      IO::Socket::INET => 0,
      IO::Socket::INET6 => 0,
      IO::Select => 0,
      LWP::UserAgent => 0,
      Net::Frame => '1.07',
      Net::Frame::Device => 0,
      Net::Frame::Dump => '1.12',
      Net::Frame::Layer::IPv6 => 0,
      Net::Frame::Layer::SinFP3 => 0,
      Net::Frame::Simple => 0,
      Net::Libdnet => '0.90',
      Net::Netmask => 0,
      Net::Write => 0,
      Parallel::ForkManager => 0,
      POSIX => 0,
      Socket => 0,
      Socket6 => 0,
      Time::Interval => 0,
   },
   EXE_FILES        => [ 'bin/sinfp3.pl', 'bin/sinfp3.db', ],
   AUTHOR           => 'GomoR <gomor_at_networecon.com>',
   MIN_PERL_VERSION => '5.6.1',
);
