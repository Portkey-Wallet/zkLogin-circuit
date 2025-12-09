pragma circom 2.0.0;
include "./sha256.circom";
include "./utils.circom";

template IdHashSha256(sub_bytes, salt_bytes){
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
