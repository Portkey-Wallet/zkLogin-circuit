pragma circom 2.0.0;
include "./sha256.circom";
include "./string.circom";
include "circomlib/circuits/bitify.circom";


template BitsToBytes(bits){
  signal input in[bits];
  signal output out[bits/8];
  for (var i=0; i<bits/8; i++) {
    var bytevalue = 0;
    for (var j=0; j<8; j++) {
      bytevalue |= in[i * 8 + j] ? (1 << (7-j)) : 0;
    }
    out[i] <-- bytevalue;
  }
}


template GuardianIdentifierHash(sub_bytes, salt_bytes){
  // inputs
  signal input sub[sub_bytes];
  signal input salt[salt_bytes];
  signal output out[32];

  component HASH1 = Sha256Bytes(sub_bytes);
  HASH1.in_padded <== sub;
  HASH1.in_len_padded_bytes <== sub_bytes;
  
  var hash2_bytes = salt_bytes + 32;

  component bitsToBytes = BitsToBytes(256);
  bitsToBytes.in <== HASH1.out;
  
  component COMBINED = CombineBytes(32, salt_bytes);

  COMBINED.first <== bitsToBytes.out;
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
