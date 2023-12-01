pragma circom 2.0.0;
include "./sha256.circom";

template GuardianIdentifierHash(sub_len, salt_len){
  var i;

  component HASH1 = Sha256String(sub_len);
  signal input sub[sub_len];
  HASH1.text <== sub;

  var hash2_len = salt_len + 256;

  component HASH2 = Sha256String(hash2_len);
  signal input salt[salt_len];
  for (i=0; i<salt_len; i++) {
    HASH2.text[i] <== salt[i];
  }
  for (i=0; i<256; i++) {
    HASH2.text[i+salt_len] <== HASH1.sha[i];
  }

  signal output hash[256];
  hash <== HASH2.sha;
}