pragma circom 2.0.0;
include "./sha256.circom";
include "./string.circom";

template GuardianIdentifierHash(sub_bytes, salt_bytes){
  component HASH1 = Hash1(sub_bytes);
  signal input sub[sub_bytes];
  HASH1.sub <== sub;
  
  component HASH2 = Hash2(256, salt_bytes);
  signal input salt[salt_bytes];
  HASH2.hash1 <== HASH1.sha;
  HASH2.salt <== salt;

  signal output sha[256];
  sha <== HASH2.sha;
}

template Hash1(sub_bytes){
  component HASH1 = Sha256Bytes(sub_bytes);
  signal input sub[sub_bytes];
  HASH1.text <== sub;

  signal output sha[256];
  sha <== HASH1.sha;
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