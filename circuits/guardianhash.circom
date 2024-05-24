pragma circom 2.0.0;
include "./helpers/jwt.circom";
include "./helpers/guardian-identifier-hash.circom";
include "./helpers/base64.circom";
include "./helpers/jwt-sub-extract.circom";
include "./helpers/jwtchecks.circom";

template GuardianHash(){
  var maxJwtLen = 1024;
  var maxSubLen = 32; // Suport sub of length 32 first
  var maxSubNameLen = 5;
  var maxSubValueLen = maxSubLen + 2; // 2 for double quotes
  var maxWhiteSpaceLen = 2; // actually we don't need this
  var maxSubClaimLen = maxSubNameLen + maxSubValueLen + maxWhiteSpaceLen; // TODO: Check if this calculation is correct 

  var maxExpLen = 10;
  var maxExpNameLen = 5;
  var maxExpValueLen = maxExpLen;
  var maxExpClaimLen = maxExpNameLen + maxExpValueLen + maxWhiteSpaceLen; // TODO: Check if this calculation is correct

  var maxNonceLen = 64;
  var maxNonceNameLen = 7;
  var maxNonceValueLen = maxNonceLen + 2; // 2 for double quotes
  var colonAndCommaLen = 2;
  var maxNonceClaimLen = maxNonceNameLen + maxNonceValueLen + maxWhiteSpaceLen + colonAndCommaLen; // TODO: Check if this calculation is correct

  signal input jwt[maxJwtLen];
  signal input signature[17];
  signal input pubkey[17];
  signal input salt[16]; // public
  signal input payload_start_index;
  signal input sub_claim[maxSubClaimLen];
  signal input sub_claim_length;
  signal input sub_index_b64;
  signal input sub_length_b64;
  signal input sub_name_length; // with quotes
  signal input sub_colon_index;
  signal input sub_value_index;
  signal input sub_value_length; // with quotes

  signal input exp_claim[maxExpClaimLen];
  signal input exp_claim_length;
  signal input exp_index_b64;
  signal input exp_length_b64;
  signal input exp_name_length; // with quotes
  signal input exp_colon_index;
  signal input exp_value_index;
  signal input exp_value_length;

  signal input nonce_claim[maxNonceClaimLen];
  signal input nonce_claim_length;
  signal input nonce_index_b64;
  signal input nonce_length_b64;
  signal input nonce_name_length; // with quotes
  signal input nonce_colon_index;
  signal input nonce_value_index;
  signal input nonce_value_length;

  signal output out[32];

  component VERIFYJWT = JWTVerify(maxJwtLen, 121, 17);
  component HASH = GuardianIdentifierHash(maxSubLen, 16);

  // Extract exp claim

  signal output exp_value[maxExpValueLen];
  component expExtClaimOps = ExtClaimOps(maxJwtLen, maxExpClaimLen, maxExpNameLen, maxExpValueLen, maxWhiteSpaceLen);
  expExtClaimOps.content <== jwt;
  expExtClaimOps.index_b64 <== exp_index_b64;
  expExtClaimOps.length_b64 <== exp_length_b64;

  expExtClaimOps.ext_claim <== exp_claim;
  expExtClaimOps.ext_claim_length <== exp_claim_length;
  expExtClaimOps.name_length <== exp_name_length; // with quotes
  expExtClaimOps.colon_index <== exp_colon_index;
  expExtClaimOps.value_index <== exp_value_index;
  expExtClaimOps.value_length <== exp_value_length; // with quotes
  expExtClaimOps.payload_start_index <== payload_start_index;


  expExtClaimOps.claim_name === [34, 101, 120, 112, 34]; // '"exp"'
  exp_value <== expExtClaimOps.claim_value;


  // Extract nonce claim

  signal output nonce_value_with_quotes[maxNonceValueLen];
  component nonceExtClaimOps = ExtClaimOps(maxJwtLen, maxNonceClaimLen, maxNonceNameLen, maxNonceValueLen, maxWhiteSpaceLen);
  nonceExtClaimOps.content <== jwt;
  nonceExtClaimOps.index_b64 <== nonce_index_b64;
  nonceExtClaimOps.length_b64 <== nonce_length_b64;

  nonceExtClaimOps.ext_claim <== nonce_claim;
  nonceExtClaimOps.ext_claim_length <== nonce_claim_length;
  nonceExtClaimOps.name_length <== nonce_name_length; // with quotes
  nonceExtClaimOps.colon_index <== nonce_colon_index;
  nonceExtClaimOps.value_index <== nonce_value_index;
  nonceExtClaimOps.value_length <== nonce_value_length; // with quotes
  nonceExtClaimOps.payload_start_index <== payload_start_index;


  nonceExtClaimOps.claim_name === [34, 110, 111, 110, 99, 101, 34]; // '"nonce"'
  nonce_value_with_quotes <== nonceExtClaimOps.claim_value;


  signal output nonce[maxNonceLen] <== QuoteRemover(maxNonceValueLen)(
      nonce_value_with_quotes, nonce_value_length
  );



  // Extract sub claim
  signal sub_value_with_quotes[maxSubValueLen];
  component subExtClaimOps = ExtClaimOps(maxJwtLen, maxSubClaimLen, maxSubNameLen, maxSubValueLen, maxWhiteSpaceLen);
  subExtClaimOps.content <== jwt;
  subExtClaimOps.index_b64 <== sub_index_b64;
  subExtClaimOps.length_b64 <== sub_length_b64;

  subExtClaimOps.ext_claim <== sub_claim;
  subExtClaimOps.ext_claim_length <== sub_claim_length;
  subExtClaimOps.name_length <== sub_name_length; // with quotes
  subExtClaimOps.colon_index <== sub_colon_index;
  subExtClaimOps.value_index <== sub_value_index;
  subExtClaimOps.value_length <== sub_value_length; // with quotes
  subExtClaimOps.payload_start_index <== payload_start_index;


  subExtClaimOps.claim_name === [34, 115, 117, 98, 34]; // '"sub"'
  sub_value_with_quotes <== subExtClaimOps.claim_value;

  signal sub[maxSubLen] <== QuoteRemover(maxSubValueLen)(
      sub_value_with_quotes, sub_value_length
  );



  // verify that the jwt is valid and not tampered with
  VERIFYJWT.jwt <== jwt;
  VERIFYJWT.signature <== signature;
  VERIFYJWT.pubkey <== pubkey;
  
  HASH.sub <== sub;
  HASH.sub_len <== sub_value_length - 2;
  HASH.salt <== salt;
  HASH.salt_len <== 16;

  out <== HASH.out;
}

component main {public [pubkey, salt]} = GuardianHash();