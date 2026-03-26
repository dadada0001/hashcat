#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Digest::MD5 qw (md5);

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $data = shift;

  my $salt_bin = pack ("H*", $salt);

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

    # verify mode: decrypt and re-encrypt

    my $aes = Crypt::CBC->new ({
      cipher      => "Crypt::Rijndael",
      key         => $key,
      iv          => $iv,
      keysize     => 32,
      literal_key => 1,
      header      => "none",
      padding     => "standard",
    });

    my $dec_bin = $aes->decrypt ($data_bin);

    # re-encrypt to verify
    $data_bin = $dec_bin;
  }
  else
  {
    # generate mode: create random plaintext

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

  my $hash = sprintf ('$cryptojs$%s$%s', unpack ("H*", $salt_bin), unpack ("H*", $enc_bin));

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

  my (undef, $signature, $salt, $data) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $salt;
  return unless defined $data;

  return unless ($signature eq 'cryptojs');
  return unless (length ($salt) == 16);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $data);

  return ($new_hash, $word);
}

1;
