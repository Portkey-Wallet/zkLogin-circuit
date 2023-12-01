pragma circom 2.0.0;
include "./helpers/jwt.circom";
include "./helpers/guardian-identifier-hash.circom";

template Main(){
  // verify that the JWT is valid
  component VERIFYJWT = JWTVerify(512, 121, 17);
  signal input jwt;       // JWT
  signal input signature; // Signature
  signal input pubkey;    // Public key

  VERIFYJWT.jwt = jwt;
  VERIFYJWT.signature = signature;
  VERIFYJWT.pubkey = pubkey;

  signal input sub;
  signal input salt;
  component HASH = GuardianIdentifierHash(512);
  HASH.sub = sub;
  HASH.salt = salt;

  signal output out[256];
  out <== HASH.out;
}

component main { public [ signature, pubkey ] } = Main();