pragma circom 2.0.0;
include "./sha256.circom";
include "./string.circom";
include "./utils.circom";
include "circomlib/circuits/bitify.circom";

template Sha254Hash(sub_bytes){
  signal input sub[sub_bytes];
  signal input sub_len;
  signal output out[32];

  var max_padded_len = (sub_bytes + 9) + (64 - (sub_bytes + 9) % 64);

  var paddedBytes[max_padded_len];
  for (var i = 0; i < sub_len; i++) {
      paddedBytes[i] = sub[i];
  }

  for (var i = sub_len; i < max_padded_len; i++) {
      paddedBytes[i] = 0;
  }

  component sha256Pad = Sha256PadBytes(max_padded_len);
  sha256Pad.in <-- paddedBytes;
  sha256Pad.in_bytes <== sub_len;

  component sha256BB = Sha256BytesOutputBytes(max_padded_len);
  
  sha256BB.in_padded <== sha256Pad.padded_text;
  sha256BB.in_len_padded_bytes <== sha256Pad.padded_len;
  out <== sha256BB.out;
}

template HashAndCombine(sub_bytes, salt_bytes){
  // inputs
  signal input sub[sub_bytes];
  signal input sub_len;
  signal input salt[salt_bytes];
  signal output out[32+salt_bytes];

  component sha254Hash = Sha254Hash(sub_bytes);
  sha254Hash.sub <== sub;
  sha254Hash.sub_len <== sub_len;
  
  var hash2_bytes = salt_bytes + 32;
  
  component combined = CombineBytes(32, salt_bytes);
  combined.first <== sha254Hash.out;
  combined.second <== salt;
  out <== combined.out;
}

template GuardianIdentifierHash(sub_bytes, salt_bytes){
  // inputs
  signal input sub[sub_bytes];
  signal input sub_len;
  signal input salt[salt_bytes];
  signal input salt_len;
  signal output out[32];

  component hashAndCombine = HashAndCombine(sub_bytes, salt_bytes);
  hashAndCombine.sub <== sub;
  hashAndCombine.sub_len <== sub_len;
  hashAndCombine.salt <== salt;
  
  var hash2_bytes = salt_bytes + 32;

  var paddedBytes[640];
  for (var i = 0; i < 32 + salt_bytes; i++) {
      paddedBytes[i] = hashAndCombine.out[i];
  }

  for (var i = 32 + salt_bytes; i < 640; i++) {
      paddedBytes[i] = 0;
  }

  component sha256Pad = Sha256PadBytes(640);
  sha256Pad.in <== paddedBytes;
  sha256Pad.in_bytes <== 32 + salt_len;

  component HASH2 = Sha256BytesOutputBytes(640);
  
  HASH2.in_padded <== sha256Pad.padded_text;
  HASH2.in_len_padded_bytes <== sha256Pad.padded_len;
  out <== HASH2.out;
}
