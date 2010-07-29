#!/usr/bin/perl
use strict;
use warnings;

open FILE, $ARGV[0].".cbc" or die $!;
print "static const char* builtin_bc_".$ARGV[0]." = ";
while (<FILE>) {
  chomp;
  if (/^S/) {
    last;
  }
  print "\"$_\\n\"\n";
}
close FILE;
print ";\n";
print "/* source-code for builtin_bc_$ARGV[0]: */\n#if 0\n";
local $/ = undef;
open FILE, $ARGV[0].".c" or die $!;
my $src = <FILE>;
close FILE;
print "$src\n#endif\n";
