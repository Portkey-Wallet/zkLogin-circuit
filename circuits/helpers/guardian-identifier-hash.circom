pragma circom 2.0.0;
include "./sha256.circom";

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
  component HASH1 = Sha256String(sub_bytes);
  signal input sub[sub_bytes];
  HASH1.text <== sub;

  signal output sha[256];
  sha <== HASH1.sha;
}

template Hash2(hash1_bytes, salt_bytes){
  signal input hash1[hash1_bytes];

  var hash2_bytes = hash1_bytes + salt_bytes;

  component HASH2 = Sha256String(hash2_bytes);
  signal input salt[salt_bytes];

  for(var i = 0; i < salt_bytes; i++){
    HASH2.text[i] <== salt[i];
  }

  for(var i = salt_bytes; i < hash2_bytes; i++){
    HASH2.text[i] <== hash1[i - salt_bytes];
  }

  signal output sha[256];
  sha <== HASH2.sha;
}