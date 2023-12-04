pragma circom 2.0.0;
include "./helpers/jwt.circom";
include "./helpers/guardian-identifier-hash.circom";

template GuardianHash(){
  component VERIFYJWT = JWTVerify(512, 121, 17);
  signal input jwt[512];
  signal input signature[17];
  signal input pubkey[17];

  VERIFYJWT.jwt <== jwt;
  VERIFYJWT.signature <== signature;
  VERIFYJWT.pubkey <== pubkey;

  signal input sub[512];
  signal input salt[512]; // public
  component HASH = GuardianIdentifierHash(512, 512);
  HASH.sub <== sub;
  HASH.salt <== salt;

  signal output out[256];
  out <== HASH.hash;
}

component main = GuardianHash();