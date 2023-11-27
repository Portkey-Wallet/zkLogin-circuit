pragma circom 2.0.0;
include "../node_modules/circomlib/circuits/sha256/sha256.circom";
template Test(){
  // length of google jwt sub
  component SHA = Sha256(21);
  signal input sub[21];
  SHA.in <== sub;

  signal output sub_out[256];
  sub_out <== SHA.out;
}

component main = Test();