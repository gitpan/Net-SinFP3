#
# $Id: Active.pm 2194 2012-11-13 20:55:10Z gomor $
#
package Net::SinFP3::Search::Active;
use strict;
use warnings;

use base qw(Net::SinFP3::Search);
our @AS = qw(
   s1
   s2
   s3
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

use Net::SinFP3 qw(:matchType :matchMask);

use Net::SinFP3::Ext::S;
use Net::SinFP3::Result::Active;
use Net::SinFP3::Result::PortError;
use Net::SinFP3::Result::Unknown;

use Net::Frame::Layer::TCP qw(:consts);

use Data::Dumper;

sub take {
   return [
      'Net::SinFP3::Mode::Active',
   ];
}

sub new {
   my $self = shift->SUPER::new(
      @_,
   );

   return $self;
}

sub _getPossibleSignatureIds {
   my $self = shift;
   my ($probe, $sig) = @_;

   my $global = $self->global;
   my $log    = $global->log;
   my $db     = $global->db;

   my %patterns = (
      PatternBinary     => 'B',
      PatternTcpFlags   => 'F',
      PatternTcpWindow  => 'W',
      PatternTcpOptions => 'O',
      PatternTcpMss     => 'M',
      PatternTcpWScale  => 'S',
      PatternTcpOLength => 'L',
   );
   my %results = ();
   for my $tPattern (keys %patterns) {
      my $pId             = "id$tPattern";
      my $signatureMethod = "id$probe"."$tPattern";
      # $sig->{S1}->{B} for instance
      my $p               = $sig->{$probe}->{$patterns{$tPattern}};

      my $_table = "_$tPattern";
      my %ids    = ();
      for my $h ('Heuristic0', 'Heuristic1', 'Heuristic2') {
         for my $t ($db->$_table) {
            (my $method = $tPattern.$h) =~ s/^(.)(.*)$/@{[lc($1)]}$2/;
            # We match either using regexp from DB, 
            # or regexp built in passive mode
            if ($p =~ /^@{[$t->{$method}]}$/ || $t->{$method} =~ /$p/) {
               #print "DEBUG: [$p] against [".$t->{$method}."]\n";
               my $id   = $t->{$pId};
               my $list = $db->searchSignatureIds(
                  $signatureMethod => $id,
               );
               for (@$list) {
                  $ids{$h}->{$_->{idSignature}}++;
                  #print "DEBUG: possibleId [$id]\n";
               }
            }
         }
      }
      $results{$patterns{$tPattern}} = \%ids;
   }
   #print "DEBUG: [$probe]_getPossibleSignatureIds: ",
      #Dumper(\%results),"\n";
   return \%results;
}

sub _searchSmallestHeuristicHash {
   my $self = shift;
   my ($heuristic, @patterns) = @_;

   my @ids  = ();
   my $last = 10_000; # Invalid huge number
   for my $pList (@patterns) {
      my $count = keys %{$pList->{$heuristic}};
      next if $count == 0;  # We need to skip, otherwise there is a bug ;)
      if ($count < $last) {
         @ids  = keys %{$pList->{$heuristic}};
         $last = $count;
      }
   }
   return \@ids;
}

sub _searchSmallestHashWithMask {
   my $self = shift;

   my @ids  = ();
   my $last = 10_000; # Invalid huge number
   for my $pList (@_) {
      my $count = keys %$pList;
      next if $count == 0;  # We need to skip, otherwise there is a bug ;)
      if ($count < $last) {
         @ids  = keys %$pList;
         $last = $count;
      }
   }
   return \@ids;
}

sub _getIntersection {
   my $self = shift;
   my ($bList, $fList, $wList, $oList, $mList, $sList, $lList) = @_;

   my $inter;
   for my $h ('Heuristic0', 'Heuristic1', 'Heuristic2') {
      my $smallest = $self->_searchSmallestHeuristicHash(
         $h, $bList, $fList, $wList, $oList, $mList, $sList, $lList,
      );
      #print "[*] DEBUG: _getIntersection: _searchSmallestHeuristicHash[$h]: ",Dumper($smallest),"\n";
      for my $id (@$smallest) {
         if (($bList->{Heuristic0}->{$id} || $bList->{Heuristic1}->{$id} || $bList->{Heuristic2}->{$id})
         &&  ($fList->{Heuristic0}->{$id} || $fList->{Heuristic1}->{$id} || $fList->{Heuristic2}->{$id})
         &&  ($wList->{Heuristic0}->{$id} || $wList->{Heuristic1}->{$id} || $wList->{Heuristic2}->{$id})
         &&  ($oList->{Heuristic0}->{$id} || $oList->{Heuristic1}->{$id} || $oList->{Heuristic2}->{$id})
         &&  ($mList->{Heuristic0}->{$id} || $mList->{Heuristic1}->{$id} || $mList->{Heuristic2}->{$id})
         &&  ($sList->{Heuristic0}->{$id} || $sList->{Heuristic1}->{$id} || $sList->{Heuristic2}->{$id})
         &&  ($lList->{Heuristic0}->{$id} || $lList->{Heuristic1}->{$id} || $lList->{Heuristic2}->{$id})) {
            my $b = $bList->{Heuristic0}->{$id} && 'BH0'
                 || $bList->{Heuristic1}->{$id} && 'BH1'
                 || $bList->{Heuristic2}->{$id} && 'BH2';
            my $f = $fList->{Heuristic0}->{$id} && 'FH0'
                 || $fList->{Heuristic1}->{$id} && 'FH1'
                 || $fList->{Heuristic2}->{$id} && 'FH2';
            my $w = $wList->{Heuristic0}->{$id} && 'WH0'
                 || $wList->{Heuristic1}->{$id} && 'WH1'
                 || $wList->{Heuristic2}->{$id} && 'WH2';
            my $o = $oList->{Heuristic0}->{$id} && 'OH0'
                 || $oList->{Heuristic1}->{$id} && 'OH1'
                 || $oList->{Heuristic2}->{$id} && 'OH2';
            my $m = $mList->{Heuristic0}->{$id} && 'MH0'
                 || $mList->{Heuristic1}->{$id} && 'MH1'
                 || $mList->{Heuristic2}->{$id} && 'MH2';
            my $s = $sList->{Heuristic0}->{$id} && 'SH0'
                 || $sList->{Heuristic1}->{$id} && 'SH1'
                 || $sList->{Heuristic2}->{$id} && 'SH2';
            my $l = $lList->{Heuristic0}->{$id} && 'LH0'
                 || $lList->{Heuristic1}->{$id} && 'LH1'
                 || $lList->{Heuristic2}->{$id} && 'LH2';
            $inter->{"$b$f$w$o$m$s$l"}->{$id}++;
         }
      }
      # Stop if we found matches with this smallest heuristic level
      #last if keys %$inter > 0;
   }
   return $inter;
}

sub _getIntersectionWithMask {
   my $self = shift;
   my ($bList, $fList, $wList, $oList, $mList, $sList, $lList, $mask) = @_;

   my $b = $mask =~ /BH0/ && 'Heuristic0'
        || $mask =~ /BH1/ && 'Heuristic1'
        || $mask =~ /BH2/ && 'Heuristic2';
   my $f = $mask =~ /FH0/ && 'Heuristic0'
        || $mask =~ /FH1/ && 'Heuristic1'
        || $mask =~ /FH2/ && 'Heuristic2';
   my $w = $mask =~ /WH0/ && 'Heuristic0'
        || $mask =~ /WH1/ && 'Heuristic1'
        || $mask =~ /WH2/ && 'Heuristic2';
   my $o = $mask =~ /OH0/ && 'Heuristic0'
        || $mask =~ /OH1/ && 'Heuristic1'
        || $mask =~ /OH2/ && 'Heuristic2';
   my $m = $mask =~ /MH0/ && 'Heuristic0'
        || $mask =~ /MH1/ && 'Heuristic1'
        || $mask =~ /MH2/ && 'Heuristic2';
   my $s = $mask =~ /SH0/ && 'Heuristic0'
        || $mask =~ /SH1/ && 'Heuristic1'
        || $mask =~ /SH2/ && 'Heuristic2';
   my $l = $mask =~ /LH0/ && 'Heuristic0'
        || $mask =~ /LH1/ && 'Heuristic1'
        || $mask =~ /LH2/ && 'Heuristic2';

   # We force a search using a very specific heuristic mask
   my $smallest = $self->_searchSmallestHashWithMask(
      $bList->{$b}, $fList->{$f}, $wList->{$w}, $oList->{$o}, $mList->{$m},
      $sList->{$s}, $lList->{$l},
   );

   my $inter;
   for my $id (@$smallest) {
      for my $id (@$smallest) {
         if ($bList->{$b}->{$id}
         &&  $fList->{$f}->{$id}
         &&  $wList->{$w}->{$id}
         &&  $oList->{$o}->{$id}
         &&  $mList->{$m}->{$id}
         &&  $sList->{$s}->{$id}
         &&  $lList->{$l}->{$id}) {
            $inter->{$mask}->{$id}++;
         }
      }
   }
   return $inter;
}

sub _searchCommonMasksS1S2S3 {
   my $self = shift;
   my ($s1Inter, $s2Inter, $s3Inter) = @_;

   my %maskList = map { $_ => 1 }
      ( keys %$s1Inter, keys %$s2Inter, keys %$s3Inter );

   my @maskList = ();
   for my $mask (keys %maskList) {
      if (exists $s1Inter->{$mask}
      &&  exists $s2Inter->{$mask}
      &&  exists $s3Inter->{$mask}) {
         push @maskList, $mask;
      }
   }
   return \@maskList;
}

sub _searchCommonMasksS1S2 {
   my $self = shift;
   my ($s1Inter, $s2Inter) = @_;

   my %maskList = map { $_ => 1 } ( keys %$s1Inter, keys %$s2Inter );

   my @maskList = ();
   for my $mask (keys %maskList) {
      if (exists $s1Inter->{$mask} && exists $s2Inter->{$mask}) {
         push @maskList, $mask;
      }
   }
   return \@maskList;
}

sub _searchSmallestInterWithMask {
   my $self = shift;

   my @ids  = ();
   my $last = 10_000; # Invalid huge number
   for my $inter (@_) {
      my $count = keys %$inter;
      next if $count == 0;   # We need to skip, otherwise there is a bug ;)
      if ($count < $last) {
         @ids  = keys %$inter;
         $last = $count;
      }
   }
   return \@ids;
}

sub _getIntersectionS1S2S3 {
   my $self = shift;
   my ($s1Inter, $s2Inter, $s3Inter) = @_;

   # Search common masks
   my $maskList = $self->_searchCommonMasksS1S2S3(
      $s1Inter, $s2Inter, $s3Inter,
   );
   #print Dumper($s1Inter),"\n";
   #print Dumper($s2Inter),"\n";
   #print Dumper($s3Inter),"\n";
   return unless @$maskList > 0;
   #print "DEBUG: found commonMasksS1S2S3 [@$maskList]\n";

   my $inter = {};
   for my $mask (@$maskList) {
      my $smallest = $self->_searchSmallestInterWithMask(
         $s1Inter->{$mask}, $s2Inter->{$mask}, $s3Inter->{$mask},
      );

      for my $id (@$smallest) {
         if ($s1Inter->{$mask}->{$id}
         &&  $s2Inter->{$mask}->{$id}
         &&  $s3Inter->{$mask}->{$id}) {
            #print "DEBUG: interS1S2S3 [$id] [$mask]\n";
            $inter->{$mask}->{$id}++;
         }
      }
   }
   return $inter;
}

sub _getIntersectionS1S2 {
   my $self = shift;
   my ($s1Inter, $s2Inter) = @_;

   # Search common masks
   my $maskList = $self->_searchCommonMasksS1S2($s1Inter, $s2Inter);
   return unless @$maskList > 0;
   #print "DEBUG: found commonMasksS1S2 [@$maskList]\n";

   my $inter = {};
   for my $mask (@$maskList) {
      my $smallest = $self->_searchSmallestInterWithMask(
         $s1Inter->{$mask}, $s2Inter->{$mask},
      );

      for my $id (@$smallest) {
         if ($s1Inter->{$mask}->{$id} && $s2Inter->{$mask}->{$id}) {
            #print "DEBUG: interS1S2 [$id] [$mask]\n";
            $inter->{$mask}->{$id}++;
         }
      }
   }
   return $inter;
}

sub _countInter {
   my $self = shift;
   my ($ids) = @_;
   for ('S1', 'S2', 'S3') {
      $ids->{$_}{nInter} = keys %{$ids->{$_}{Inter}};
      #print "[*] _countInter[$_]: ".$ids->{$_}{nInter}."\n";
   }
   return $ids;
}

sub _tohash {
   my $self = shift;
   my ($s) = @_;
   return {
      B => $self->$s->B,
      F => $self->$s->F,
      W => $self->$s->W,
      O => $self->$s->O,
      M => $self->$s->M,
      S => $self->$s->S,
      L => $self->$s->L,
   };
}

sub _search {
   my $self = shift;

   my $global = $self->global;
   my $log    = $global->log;

   # Convert it to optimize a bit
   my $s1 = $self->s1 && $self->_tohash('s1') || undef;
   my $s2 = $self->s2 && $self->_tohash('s2') || undef;
   my $s3 = $self->s3 && $self->_tohash('s3') || undef;

   my %sig = (
      'S1' => $s1,
      'S2' => $s2,
      'S3' => $s3,
   );

   my $ids = {};
   for my $s (keys %sig) {
      if ($sig{$s}) {
         my $res   = $self->_getPossibleSignatureIds($s, \%sig);
         #$log->debug("_getPossibleSignatureIds[$s]: ".Dumper($res));
         my $inter = $self->_getIntersection(
            $res->{B}, $res->{F}, $res->{W}, $res->{O}, $res->{M},
            $res->{S}, $res->{L},
         );
         $ids->{$s}{Ids}   = $res;
         $ids->{$s}{Inter} = $inter;
         #$log->debug("inter[$s]: ".Dumper($inter));
      }
   }

   # Make masks unique
   my %maskList = map { $_ => 1 } (
      keys %{$ids->{S1}{Inter}},
      keys %{$ids->{S2}{Inter}},
      keys %{$ids->{S3}{Inter}},
   );

   # Update number of resulting intersection for S1, S2 and S3
   $self->_countInter($ids);

   #print "[*] maskList: ".join(' ', keys %maskList)."\n";

   # For all masks, expand possible Signature IDs to make 
   # all of them comparable
   for my $mask (keys %maskList) {
      for my $p ('S1', 'S2', 'S3') {
         #if ($ids->{S1}{nInter} > 0 && ! exists $ids->{S1}{Ier}->{$mk}) {
         #print "[*] ".Dumper($ids->{$p}{Ids})."\n";
         if (!exists $ids->{$p}{Inter}->{$mask}) {
            #print "[*] Running with [$mask] against [$p]\n";
            my $interNew = $self->_getIntersectionWithMask(
               $ids->{$p}{Ids}->{B}, $ids->{$p}{Ids}->{F}, 
               $ids->{$p}{Ids}->{W}, $ids->{$p}{Ids}->{O}, 
               $ids->{$p}{Ids}->{M}, $ids->{$p}{Ids}->{S}, 
               $ids->{$p}{Ids}->{L}, $mask,
            );
            if ($interNew) {
               #print "[*] interNew[$p]: ".Dumper($interNew)."\n";
               $ids->{$p}{Inter}->{$mask} = $interNew->{$mask};
            }
         }
      }
   }
   #$log->debug("s1InterNew: ".Dumper($ids->{S1}{Inter}));
   #$log->debug("s2InterNew: ".Dumper($ids->{S2}{Inter}));
   #$log->debug("s3InterNew: ".Dumper($ids->{S3}{Inter}));

   # Update number of resulting intersection for S1, S2 and S3
   # after we have expanded mask list
   $self->_countInter($ids);

   my @resultList = ();

   # Some matchs were found for all probes
   if ($ids->{S1}{nInter} > 0
   &&  $ids->{S2}{nInter} > 0
   &&  $ids->{S3}{nInter} > 0) {
      my $s1s2s3 = $self->_getIntersectionS1S2S3(
         $ids->{S1}{Inter}, $ids->{S2}{Inter}, $ids->{S3}{Inter},
      );
      if (keys %$s1s2s3 > 0) {
         #print "DEBUG: NS_MATCH_TYPE_S1S2S3\n";
         my $results = $self->_buildResultList(
            $s1s2s3, NS_MATCH_TYPE_S1S2S3,
         );
         push @resultList, @$results;
      }
   }

   # Matchs for only S1 and S2
   if ($ids->{S1}{nInter} > 0 && $ids->{S2}{nInter} > 0) {
      my $s1s2 = $self->_getIntersectionS1S2(
         $ids->{S1}{Inter}, $ids->{S2}{Inter},
      );
      if (keys %$s1s2 > 0) {
         #print "DEBUG: NS_MATCH_TYPE_S1S2\n";
         my $results = $self->_buildResultList($s1s2, NS_MATCH_TYPE_S1S2);
         push @resultList, @$results;
      }
   }

   # Match with S2 only
   if ($ids->{S2}{nInter} > 0) {
      #print "DEBUG: NS_MATCH_TYPE_S2\n";
      my $results = $self->_buildResultList(
         $ids->{S2}{Inter}, NS_MATCH_TYPE_S2,
      );
      push @resultList, @$results;
   }

   my $clean4 = $self->_cleanResults(\@resultList, 'IPv4');
   my $clean6 = $self->_cleanResults(\@resultList, 'IPv6');

   # We keep IPv4 signatures in IPv6 mode only if no IPv6 matchs
   # Else in IPv4 mode, we only keep IPv4 matchs
   my @clean = ();
   if ($self->global->ipv6 && @$clean6 > 0) {
      push @clean, @$clean6;
   }
   elsif (@$clean4 > 0) {
      push @clean, @$clean4;
   }

   return \@clean;
}

sub _cleanResults {
   my $self = shift;
   my ($results, $ip) = @_;

   my $global = $self->global;
   my $log    = $global->log;

   # Sort to easily filter out
   my $sorted = {};
   for my $r (@$results) {
      if ($r->ipVersion ne $ip) {
         next;
      }
      if ($global->threshold != 0 && $r->matchScore < $global->threshold) {
         next;
      }
      push @{$sorted->{$r->matchType}{$r->matchScore}}, $r;
   }

   my $s1s2s3 = $sorted->{NS_MATCH_TYPE_S1S2S3()};
   my $s1s2   = $sorted->{NS_MATCH_TYPE_S1S2()};
   my $s2     = $sorted->{NS_MATCH_TYPE_S2()};

   # If some scores are lower than or equal for lower matchTypes, we remove
   # First case we have some S1S2S3 matchs
   my @sorted2 = ();
   if (keys %$s1s2s3 > 0) {
      for my $src (keys %$s1s2s3) {
         for my $dst (keys %$s1s2, keys %$s2) {
            #print "DEBUG: [$src] [$dst]\n";
            if ($dst <= $src) {
               $sorted->{NS_MATCH_TYPE_S1S2()}{$dst} = [];
               $sorted->{NS_MATCH_TYPE_S2()}{$dst}   = [];
            }
         }
      }

      # Sort results by IP version and score, keep only highest score for an ID
      my %idList    = ();
      my $bestScore = 0;
      for my $p (sort { $b <=> $a } keys %{$sorted->{NS_MATCH_TYPE_S1S2S3()}}) {
         for my $r (@{$sorted->{NS_MATCH_TYPE_S1S2S3()}{$p}}, 
                    @{$sorted->{NS_MATCH_TYPE_S1S2()}{$p}},
                    @{$sorted->{NS_MATCH_TYPE_S2()}{$p}}) {
            if (! exists($idList{$r->idSignature})) {
               if ($global->bestScore) {
                  if ($r->matchScore >= $bestScore) {
                     push @sorted2, $r;
                     $idList{$r->idSignature}++;
                     if (! $bestScore) {
                        $bestScore = $r->matchScore;
                     }
                  }
               }
               else {
                  push @sorted2, $r;
                  $idList{$r->idSignature}++;
               }
            }
         }
      }
   }
   elsif (keys %$s1s2 > 0) {
      # Second case we have some S1S2 matchs
      for my $src (keys %$s1s2) {
         for my $dst (keys %$s2) {
            if ($dst <= $src) {
               $sorted->{NS_MATCH_TYPE_S2()}{$dst} = [];
            }
         }
      }

      # Sort results by IP version and score, keep only highest score for an ID
      my %idList    = ();
      my $bestScore = 0;
      for my $p (sort { $b <=> $a } keys %{$sorted->{NS_MATCH_TYPE_S1S2()}}) {
         for my $r (@{$sorted->{NS_MATCH_TYPE_S1S2()}{$p}},
                    @{$sorted->{NS_MATCH_TYPE_S2()}{$p}}) {
            if (! exists($idList{$r->idSignature})) {
               if ($global->bestScore) {
                  if ($r->matchScore >= $bestScore) {
                     push @sorted2, $r;
                     $idList{$r->idSignature}++;
                     if (! $bestScore) {
                        $bestScore = $r->matchScore;
                     }
                  }
               }
               else {
                  push @sorted2, $r;
                  $idList{$r->idSignature}++;
               }
            }
         }
      }
   }
   elsif (keys %$s2 > 0) {
      # Third case we have some S2 matchs
      # Sort results by IP version and score, keep only highest score for an ID
      my %idList    = ();
      my $bestScore = 0;
      for my $p (sort { $b <=> $a } keys %{$sorted->{NS_MATCH_TYPE_S2()}}) {
         for my $r (@{$sorted->{NS_MATCH_TYPE_S2()}{$p}}) {
            if (! exists($idList{$r->idSignature})) {
               if ($global->bestScore) {
                  if ($r->matchScore >= $bestScore) {
                     push @sorted2, $r;
                     $idList{$r->idSignature}++;
                     if (! $bestScore) {
                        $bestScore = $r->matchScore;
                     }
                  }
               }
               else {
                  push @sorted2, $r;
                  $idList{$r->idSignature}++;
               }
            }
         }
      }
   }
   else {
      # Or no matchs at all
      return [];
   }

   return \@sorted2;
}

sub _buildResultList {
   my $self = shift;
   my ($result, $matchType) = @_;

   my $global = $self->global;
   my $log    = $global->log;
   my $db     = $global->db;
   my $next   = $global->next;

   my @resultList = ();
   for my $mask (keys %$result) {
      #$log->debug("MASK[$mask]");
      for my $id (keys %{$result->{$mask}}) {
         my %args   = ();
         my $sig    = $db->retrieveSignature($id);
         my $result = Net::SinFP3::Result::Active->new(
            global          => $self->global,
            trusted         => $sig->{trusted},
            idSignature     => $sig->{idSignature},
            ipVersion       => $sig->{ipVersion},
            systemClass     => $sig->{systemClass},
            vendor          => $sig->{vendor},
            os              => $sig->{os},
            osVersion       => $sig->{osVersion},
            osVersionFamily => $sig->{osVersionFamily},
            matchType       => $matchType,
            matchMask       => $mask,
            osVersionChildrenList => $db->getOsVersionChildrenList(
               $id,
            ),
         );
         $result->s1($self->s1) if $self->s1;
         $result->s2($self->s2) if $self->s2;
         $result->s3($self->s3) if $self->s3;
         $result->updateMatchScore;
         push @resultList, $result;
      }
   }

   return \@resultList;
}

sub _checkForTest {
   my $self = shift;
   my ($mode, $do, $pkt) = @_;

   # If this mode does not support testing
   if (! $mode->can($do) && ! $mode->can($pkt)) {
      return;
   }

   # We did not want this test
   if (($mode->can($do) && ! $mode->$do) || ! $mode->$pkt) {
      return;
   }

   # We wanted it, but we had a problem in the reply
   my $flags = $mode->$pkt->reply
      ? $mode->$pkt->reply->ref->{TCP}->flags
      : undef;

   if (! $flags) {
      return "no response (filtered port)";
   }
   elsif ($flags & NF_TCP_FLAGS_RST) {
      return "RESET by peer (closed port)";
   }

   return;
}

sub _checkPort {
   my $self = shift;
   my ($mode, $reasons) = @_;

   my $p1 = $self->_checkForTest($mode, 'doP1', 'p1');
   my $p2 = $self->_checkForTest($mode, 'doP2', 'p2');

   if ($p1 && $p2) {
      $reasons->{p1} = $p1;
      $reasons->{p2} = $p2;
      return;
   }

   # The port can be fingerprinted
   return 1;
}

sub run {
   my $self = shift->SUPER::run(@_) or return;

   my $global = $self->global;
   my $log    = $global->log;
   my $mode   = $global->mode;

   if (! $mode->s1 && ! $mode->s2 && ! $mode->s3) {
      $log->error("Nothing to search");
      return;
   }

   $self->s1($mode->s1);
   $self->s2($mode->s2);
   $self->s3($mode->s3);

   # If the port appears to be closed or filtered
   # We cannot fingerprint and return another Result object
   my $reasons = {};
   my $result  = [];
   # XXX: _checkPort() should be in Mode::Active?
   if (!$self->_checkPort($mode, $reasons)) {
      my $r = Net::SinFP3::Result::PortError->new(
         global   => $self->global,
         p1Reason => $reasons->{p1},
         p2Reason => $reasons->{p2},
      );
      $result = [ $r ];
   }
   else {
      $result = $self->_search;
      if (@$result == 0) {
         my $r = Net::SinFP3::Result::Unknown->new(
            global => $self->global,
            s1     => $mode->s1,
            s2     => $mode->s2,
            s3     => $mode->s3,
         );
         $result = [ $r ];
      }
   }

   # Fill IP/port attributes if available
   if ($mode->p2 && $mode->p2->reply) {
      my $reply = $mode->p2->reply;
      my $ip    = $reply->ref->{IPv4} || $reply->ref->{IPv6};
      my $tcp   = $reply->ref->{TCP};
      for my $r (@$result) {
         $r->ip($ip->src);
         $r->port($tcp->src);
         if ($global->dnsReverse) {
            $r->reverse($global->getAddrReverse(addr => $r->ip) || 'unknown');
         }
      }
   }
   elsif ($mode->p2) {
      my $p2  = $mode->p2;
      my $ip  = $p2->ref->{IPv4} || $p2->ref->{IPv6};
      my $tcp = $p2->ref->{TCP};
      for my $r (@$result) {
         $r->ip($ip->dst);
         $r->port($tcp->dst);
         if ($global->dnsReverse) {
            $r->reverse($global->getAddrReverse(addr => $r->ip) || 'unknown');
         }
      }
   }

   return $result;
}

1;

__END__

=head1 NAME

Net::SinFP3::Search::Active - matching active signatures search engine

=head1 DESCRIPTION

Go to http://www.networecon.com/tools/sinfp/ to know more.

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2011-2012, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
