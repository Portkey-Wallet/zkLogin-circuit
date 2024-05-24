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

  var maxNonceLen = 32;
  var maxNonceNameLen = 7;
  var maxNonceValueLen = maxNonceLen + 2; // 2 for double quotes
  var maxNonceClaimLen = maxNonceNameLen + maxNonceValueLen + maxWhiteSpaceLen; // TODO: Check if this calculation is correct

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

  /**
   *  'exp_claim': '"exp":1716453435}',
 'exp_claim_length': 17,
 'exp_index_b64': 474,
 'exp_length_b64': 23,
 'exp_name_length': 5,
 'exp_colon_index': 5,
 'exp_value_index': 6,
 'exp_value_length': 10
   */

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

  // signal output exp[maxExpLen] <== QuoteRemover(maxExpValueLen)(
  //     exp_value, exp_value_length
  // );



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