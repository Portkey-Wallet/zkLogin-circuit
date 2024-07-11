pragma circom 2.0.0;
include "./sha256.circom";
include "./string.circom";
include "./utils.circom";
include "circomlib/circuits/bitify.circom";

template Sha256PadAndHash(max_bytes){
  signal input in[max_bytes];
  signal input in_len;
  signal output out[32];

  var max_padded_len = (max_bytes + 9) + (64 - (max_bytes + 9) % 64);

  var paddedBytes[max_padded_len];
  for (var i = 0; i < in_len; i++) {
      paddedBytes[i] = in[i];
  }

  for (var i = in_len; i < max_padded_len; i++) {
      paddedBytes[i] = 0;
  }

  component sha256Pad = Sha256PadBytes(max_padded_len);
  sha256Pad.in <-- paddedBytes;
  sha256Pad.in_bytes <== in_len;

  component sha256BB = Sha256BytesOutputBytes(max_padded_len);
  
  sha256BB.in_padded <== sha256Pad.padded_text;
  sha256BB.in_len_padded_bytes <== sha256Pad.padded_len;
  out <== sha256BB.out;
}

template GuardianIdentifierHash(sub_bytes, salt_bytes){
  // inputs
  signal input sub[sub_bytes];
  signal input sub_len;
  signal input salt[salt_bytes];
  signal input salt_len;
  signal output out[32];

  // Step 1: Hash the sub value
  component subHasher = Sha256PadAndHash(sub_bytes);
  subHasher.in <== sub;
  subHasher.in_len <== sub_len;
  
  // Step 2: Combine the hash with the salt
  var hash2_bytes = salt_bytes + 32;

  component concatenated = CombineBytes(32, salt_bytes);
  concatenated.first <== subHasher.out;
  concatenated.second <== salt;

  // Step 3: Hash the concatenated value
  component idHasher = Sha256PadAndHash(hash2_bytes);
  
  idHasher.in <== concatenated.out;
  idHasher.in_len <== hash2_bytes;
  out <== idHasher.out;
}
