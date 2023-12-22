pragma circom 2.0.0;

template GuardianHash(){
  signal input jwt[512];
  signal input salt[32]; // public
  signal output out[32];

  for (var i = 0; i<32; i++) {
    out[i] <== salt[i];
  }
}

component main {public [salt]} = GuardianHash();