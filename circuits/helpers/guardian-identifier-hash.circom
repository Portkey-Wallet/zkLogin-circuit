pragma circom 2.0.0;
include "./sha256.circom";
include "./string.circom";
include "circomlib/circuits/bitify.circom";

template GuardianIdentifierHash(sub_bytes, salt_bytes){
  // inputs
  signal input sub[sub_bytes];
  signal input salt[salt_bytes];
  signal output out[64];

  component HASH1 = Sha256Bytes(sub_bytes);
  HASH1.in_padded <== sub;
  HASH1.in_len_padded_bytes <== sub_bytes;
  
  var hash2_bytes = salt_bytes + 32;
  
  component COMBINED = CombineBytes(32, salt_bytes);

  for (var i=0; i<32; i++) {
    var bytevalue = 0;
    for (var j=0; j<8; j++) {
      bytevalue |= HASH1.out[i * 8 + j] ? (1 << (7-j)) : 0;
    }
    COMBINED.first[i] <== bytevalue;
  }

  COMBINED.second <== salt;

  component sha256Pad = Sha256Pad(64);
  sha256Pad.text <== COMBINED.out;
  out <== Sha256Bytes(64)(sha256Pad.padded_text, sha256Pad.padded_len);
}

template CombineBytes(first_bytes, second_bytes) {
  // inputs
  signal input first[first_bytes];
  signal input second[second_bytes];

  signal output out[first_bytes + second_bytes];

  for (var i = 0; i < first_bytes; i++) {
      out[i] <== first[i];
  }

  for (var i = 0; i < second_bytes; i++) {
      out[i + first_bytes] <== second[i];
  }
}
