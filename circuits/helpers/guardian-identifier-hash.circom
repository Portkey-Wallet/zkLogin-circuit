pragma circom 2.0.0;
include "./sha256.circom";
include "./string.circom";

template GuardianIdentifierHash(sub_bytes, salt_bytes){
  // inputs
  signal input sub[sub_bytes];
  signal input salt[salt_bytes];

  component HASH1 = Sha256Bytes(sub_bytes);
  HASH1.in_padded <== sub;
  HASH1.in_len_padded_bytes <== sub_bytes;
  
  var hash2_bytes = salt_bytes + 256;
  component HASH2 = Sha256Bytes(hash2_bytes);
  HASH2.in_len_padded_bytes <== hash2_bytes;

  // assign the salt to the input for the second hash
  for (var i = 0; i < salt_bytes; i++) {
      HASH2.in_padded[i] <== salt[i];
  }

  // assign the hash of hash1 to the input for the second hash
  for (var i = 0; i < 256; i++) {
      HASH2.in_padded[i + salt_bytes] <== HASH1.out[i];
  }

  signal output sha[256];
  sha <== HASH2.sha;
}

template Hash2(hash1_bytes, salt_bytes){
  signal input hash1[hash1_bytes];
  signal input salt[salt_bytes];

  // salt + hash1
  component CONCAT = Concat(salt_bytes, hash1_bytes);
  CONCAT.text1 <== salt;
  CONCAT.text2 <== hash1;

  // hash(salt + hash1)
  var hash2_bytes = salt_bytes + hash1_bytes;
  component HASH2 = Sha256Bytes(hash2_bytes);
  HASH2.text <== CONCAT.out;

  signal output sha[256];
  sha <== HASH2.sha;
}