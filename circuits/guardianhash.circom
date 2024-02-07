pragma circom 2.0.0;
include "./helpers/jwt.circom";
include "./helpers/guardian-identifier-hash.circom";
include "./helpers/base64.circom";
include "./helpers/jwt-sub-extract.circom";

template GuardianHash(){
  signal input jwt[2048];
  signal input signature[17];
  signal input pubkey[17];
  signal input salt[16]; // public
  signal output out[32];

  component VERIFYJWT = JWTVerify(2048, 121, 17);
  component HASH = GuardianIdentifierHash(256, 16);
  component GETSUB = ExtractSubFromJWT(2048, 256);

  GETSUB.jwt <== jwt;

  // verify that the jwt is valid and not tampered with
  VERIFYJWT.jwt <== jwt;
  VERIFYJWT.signature <== signature;
  VERIFYJWT.pubkey <== pubkey;
  
  HASH.sub <== GETSUB.sub;
  HASH.sub_len <== GETSUB.sub_len;
  HASH.salt <== salt;
  HASH.salt_len <== 16;

  out <== HASH.out;
}

component main {public [pubkey, salt]} = GuardianHash();