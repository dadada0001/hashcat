#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Digest::MD5 qw (md5);
use MIME::Base64;

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $data = shift;

  my $salt_bin;

  if (defined $salt)
  {
    $salt_bin = pack ("H*", $salt);
  }
  else
  {
    $salt_bin = random_bytes (8);
  }

  # EVP_BytesToKey with MD5 for AES-256

  my $d1 = md5 ($word . $salt_bin);
  my $d2 = md5 ($d1 . $word . $salt_bin);
  my $d3 = md5 ($d2 . $word . $salt_bin);

  my $key = $d1 . $d2;   # 32 bytes for AES-256
  my $iv  = $d3;          # 16 bytes

  my $data_bin;

  if (defined $data)
  {
    $data_bin = pack ("H*", $data);

    my $aes = Crypt::CBC->new ({
      cipher      => "Crypt::Rijndael",
      key         => $key,
      iv          => $iv,
      keysize     => 32,
      literal_key => 1,
      header      => "none",
      padding     => "standard",
    });

    $data_bin = $aes->decrypt ($data_bin);
  }
  else
  {
    $data_bin = "CryptoJS hashcat test data for password cracking verification!";
  }

  my $aes = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    key         => $key,
    iv          => $iv,
    keysize     => 32,
    literal_key => 1,
    header      => "none",
    padding     => "standard",
  });

  my $enc_bin = $aes->encrypt ($data_bin);

  # CryptoJS format: base64("Salted__" + salt + ciphertext)

  my $raw = "Salted__" . $salt_bin . $enc_bin;
  my $b64 = encode_base64 ($raw, "");

  my $hash = sprintf ('$cryptojs$%s', $b64);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 10) eq '$cryptojs$';

  my $b64 = substr ($hash, 10);

  my $raw = decode_base64 ($b64);

  return unless length ($raw) >= 24;

  # verify "Salted__" prefix

  return unless substr ($raw, 0, 8) eq "Salted__";

  my $salt_bin = substr ($raw, 8, 8);
  my $ct_bin   = substr ($raw, 16);

  return unless length ($ct_bin) >= 16;
  return unless (length ($ct_bin) % 16) == 0;

  my $salt = unpack ("H*", $salt_bin);
  my $data = unpack ("H*", $ct_bin);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $data);

  return ($new_hash, $word);
}

1;
