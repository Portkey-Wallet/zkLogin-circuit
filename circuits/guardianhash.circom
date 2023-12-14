pragma circom 2.0.0;
include "./helpers/jwt.circom";
include "./helpers/guardian-identifier-hash.circom";
include "./helpers/base64.circom";
include "./helpers/jwt-sub-extract.circom";

template GuardianHash(){
  signal input jwt[512];
  signal input signature[17];
  signal input pubkey[17];
  signal input sub[256];
  signal input salt[32]; // public
  signal output out[32];

  component VERIFYJWT = JWTVerify(512, 121, 17);
  component HASH = GuardianIdentifierHash(256, 32);
  component GETSUB = ExtractSubFromJWT();

  GETSUB.jwt <== jwt;
  assert(GETSUB.out == sub);

  // verify that the jwt is valid and not tampered with
  VERIFYJWT.jwt <== jwt;
  VERIFYJWT.signature <== signature;
  VERIFYJWT.pubkey <== pubkey;
  
  HASH.sub <== sub;
  HASH.salt <== salt;

  out <== HASH.out;
}

component main = GuardianHash();