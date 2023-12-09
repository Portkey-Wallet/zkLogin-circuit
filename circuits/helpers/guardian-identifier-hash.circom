pragma circom 2.0.0;
include "./sha256.circom";
include "./string.circom";
include "./utils.circom";
include "circomlib/circuits/bitify.circom";

template Hash(sub_bytes){
  signal input sub[sub_bytes];
  signal input sub_len;
  signal output out[32];

  var paddedBytes[640];
  for (var i = 0; i < sub_len; i++) {
      paddedBytes[i] = sub[i];
  }

  for (var i = sub_len; i < 640; i++) {
      paddedBytes[i] = 0;
  }

  component sha256Pad = Sha256PadBytes(640);
  sha256Pad.in <-- paddedBytes;
  sha256Pad.in_bytes <== sub_len;

  component HASH1 = Sha256BytesOutputBytes(640);
  
  HASH1.in_padded <== sha256Pad.padded_text;
  HASH1.in_len_padded_bytes <== sha256Pad.padded_len;
  out <-- HASH1.out;
}

template HashAndCombine(sub_bytes, salt_bytes){
  // inputs
  signal input sub[sub_bytes];
  signal input sub_len;
  signal input salt[salt_bytes];
  signal output out[32+salt_bytes];

  component HASH1 = Hash(sub_bytes);
  HASH1.sub <== sub;
  HASH1.sub_len <== sub_len;
  
  var hash2_bytes = salt_bytes + 32;
  
  component COMBINED = CombineBytes(32, salt_bytes);
  COMBINED.first <== HASH1.out;
  COMBINED.second <== salt;
  out <-- COMBINED.out;
}

template GuardianIdentifierHash(sub_bytes, salt_bytes){
  // inputs
  signal input sub[sub_bytes];
  signal input salt[salt_bytes];
  signal output out[32];

  component HASH1 = Sha256BytesOutputBytes(sub_bytes);
  HASH1.in_padded <== sub;
  HASH1.in_len_padded_bytes <== sub_bytes;
  
  var hash2_bytes = salt_bytes + 32;
  
  component COMBINED = CombineBytes(32, salt_bytes);
  COMBINED.first <== HASH1.out;
  COMBINED.second <== salt;
  var paddedBytes[640];
  for (var i = 0; i < 32 + salt_bytes; i++) {
      paddedBytes[i] = COMBINED.out[i];
  }

  for (var i = 32 + salt_bytes; i < 640; i++) {
      paddedBytes[i] = 0;
  }

  component sha256Pad = Sha256PadBytes(640);
  sha256Pad.in <== paddedBytes;
  sha256Pad.in_bytes <== 32 + salt_bytes;

  component HASH2 = Sha256Bytes(640);

  HASH2.in_padded <== sha256Pad.padded_text;
  HASH2.in_len_padded_bytes <== sha256Pad.padded_len;

  component bitsToBytes2 = BitsToBytes(256);

  bitsToBytes2.in <== HASH2.out;
  out <-- bitsToBytes2.out;
}
