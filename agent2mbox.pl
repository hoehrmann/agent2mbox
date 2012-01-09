#!perl -w
use strict;
use warnings;
use Data::ParseBinary;
use IO::File;
use Data::Dumper;
use File::Spec;
use URI;
use URI::QueryParam;
use YAML::XS;

binmode STDOUT;

open my $idx_file, '<', $ARGV[0] or die $!;
binmode $idx_file;
my $contents = do { local $/; <$idx_file> };

my $dat_path = do {
  my $path = $ARGV[0];
  $path =~ s/\.idx$/.dat/i;
  $path;
};

open my $dat_file, '<', $dat_path or die $!;
binmode $dat_file;

my $s =
Struct("Index File",
  Struct("Header",
    Magic("\x00\x00\x00\x00\xFF\xFF\xFF\xFF"),
    ULInt32("Record Count"),
    ULInt8("Sort Code"),
    Bytes("Unknown", 19)
  ),
  Array(sub {
    $_->ctx->{"Header"}{"Record Count"} - 1;
  }, Struct("Index Entries",
      ULInt32("Start Position 512"),
      ULInt32("Id"),
      ULInt32("Srv Number"),
      ULInt32("Thread Id"),
      ULInt32("Ref Id"),
      ULInt16("Lines 128"),
      ULInt16("Flags"),
      ULInt32("Timestamp"),
      ULInt16("Header Length"),
      ULInt16("Unknown"),
     )
  ), # end of Array
  Struct("Flag Field",
    ULInt16("Length of Field"),
    # Bytes("Field Data", sub{ $_->ctx->{'Length of Field'} - 2 })
    ULInt16("When retrieving new headers"),
    ULInt16("When retrieving marked message bodies"),
    ULInt16("Unknown 1"),
    ULInt16("Purge Unread Messages w/o bodies"),
    ULInt16("Purge Unread Messages w/o bodies (time)"),
    ULInt16("Unknown 2"),
    ULInt16("Purge Unread Messages w/bodies"),
    ULInt16("Purge Unread Messages w/bodies (time)"),
    Bytes("Unknown 3", 34),
    Byte("Custom Header Count"),
    Bytes("Unknown 4", 29),
    Bytes("Unknown 5", 531),
  ),
  Struct("Header Field Strings",
    CString('From'),
    CString('Cc'),
    CString('Bcc'),
    CString('Unknown1'),
    CString('Unknown2'),
    CString('Followup-To'),
    CString('Distribution'),
    CString('Keywords'),
    CString('Summary'),
    CString('Sender'),
    CString('Organization'),
    CString('Reply-To'),
    CString('Expires'),
    CString('Newsgroups'),
  ),
  Array(8, PascalString("Various Strings", \&ULInt32)),
  Array(sub {
    $_->ctx->{'Flag Field'}{'Custom Header Count'};
  }, Struct("Custom Header",
       ULInt16("String Type?"),
       PascalString("Name", \&ULInt32),
       PascalString("Value", \&ULInt32),
     ),
  ),
  PascalString("Folder Name", \&ULInt32),
  Bytes("xxx1", 22 - 6),
  ULInt16("v1"),
  ULInt16("v2"),
  ULInt16("v3"),
  PascalString("Unknown 33", \&ULInt32),

  Bytes("v0", sub { 6 * ($_->ctx->{v1} +
    $_->ctx->{v3} + $_->ctx->{v3}) }),

  ULInt16("v4"),
  ULInt16("v5"),

  Bytes("v6", 28),

  If(sub { return $_->ctx->{v5} > 0;  },
    Struct("...",
      ULInt32("v7"),
      PascalString("v8", \&ULInt32),
      Bytes("v9", 16),
    ),
  ),

  If(sub { $_->ctx->{v5} > 1 },
    Struct("v100",
      ULInt32("v7"),
      PascalString("v10", \&ULInt32),
      ULInt32("v11"),
      ULInt32("v12"),
      If (sub { $_->ctx->{v12} },
        Bytes("v14", 8),
      ),
    ),
  ),

  Struct("Message Flags",

    Struct("Unread",
      Magic("\xFF\xFF"),
      ULInt32("Length"),
      Bytes("Data", sub { $_->ctx->{'Length'} }),
    ),
    Struct("Retrieve",
      Magic("\xFF\xFF"),
      ULInt32("Length"),
      Bytes("Data", sub { $_->ctx->{'Length'} }),
    ),
    Struct("Watch",
      Magic("\xFF\xFF"),
      ULInt32("Length"),
      Bytes("Data", sub { $_->ctx->{'Length'} }),
    ),
    Struct("Ignore",
      Magic("\xFF\xFF"),
      ULInt32("Length"),
      Bytes("Data", sub { $_->ctx->{'Length'} }),
    ),
    Struct("Keep",
      Magic("\xFF\xFF"),
      ULInt32("Length"),
      Bytes("Data", sub { $_->ctx->{'Length'} }),
    ),
    Struct("Body",
      Magic("\xFF\xFF"),
      ULInt32("Length"),
      Bytes("Data", sub { $_->ctx->{'Length'} }),
    ),
  ),

);

my $r = $s->parse($contents);

my $folder_name = $r->{'Folder Name'};
$folder_name =~ s/\x00$//;

foreach my $ix (0 .. -1 + @{ $r->{'Index Entries'} }) {
  my $entry = $r->{'Index Entries'}->[$ix];
  my $pos = $entry->{'Start Position 512'};

  if ((($pos & 0x7FFFFF) != $pos) and $pos >> 23 != 0b10100110) {
    warn "bad pointer\n";
  }

  $pos &= 0x7FFFFF;

  seek $dat_file, $pos * 512, 0 or die $!;
  read $dat_file, my $dat_block, 512 or die $!;
  die length $dat_block unless length $dat_block == 512;

  my ($dat_length, $dat_succ, @dat_data) =
    unpack "VVV126", $dat_block;

  my $length = $dat_length;
  my $article = "";

  if ($length <= 512 - 8) {
    $article = substr $dat_block, 8, $length;
  } else {
    my $blocks = int(($length + 511) / 512);
    my $rest = $length;
    my $current;

    die unless $blocks > 0;

    for ($current = 0; $current < $blocks - 1;) {
      seek $dat_file, $dat_data[$current % 126] * 512, 0 or die $!;
      read $dat_file, my $chunk, 512 or die $!;
      die unless length $chunk == 512;

      $article .= $chunk;
      $current++;
      $rest -= 512;

      if ($current % 126 == 0) {
        seek $dat_file, $dat_succ * 512, 0 or die $!;
        read $dat_file, $dat_block, 512 or die $!;
        die unless length $dat_block == 512;

        ($dat_length, $dat_succ, @dat_data) =
          unpack "VVV126", $dat_block;
      }
    }

    if ($rest > 0) {
      seek $dat_file, $dat_data[$current % 126] * 512, 0 or die $!;
      read $dat_file, my $chunk, $rest or die $!;
      die unless length $chunk == $rest;
      $article .= $chunk;
    }
  }

  my $text = $article;
  if ($text =~ /^\x00\x19/) {
    substr $text, 0, 0x20, '';
    (undef, my $len) = unpack "a8V", $text;
    $text = substr $text, 0, $len - 0x20;
  }

  my $uri = URI->new;
  while (my ($name, $value) = each %{ $r->{'Message Flags'} }) {
    $uri->query_param(lc $name, 1) if vec $value->{Data}, $ix, 1;
  }

  $uri->query_param(folder_name => $folder_name);

  my $text2 = $text;
  $text2 =~ s/^.*?\n//;
  $text2 =~ s/^(>*)From /$1>From /mg;

  my $guid1 = "E18D6C16-8251-12F7-B8DC-02717793E0F3";
  my $guid2 = "A537701F-0790-4BC4-8AD2-9B9A28AE323F";

  print "From $guid1\@example.com Thu Jan 1 00:00:00 1970\n";
  printf "X-$guid2-Flags: %s\n", $uri;
  print "$text2\n";
  print "\n";
}

# Same terms als Perl itself.
