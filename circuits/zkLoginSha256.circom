pragma circom 2.0.0;
include "./helpers/jwt-new.circom";
include "./helpers/idhash_sha256.circom";
include "./helpers/jwtchecks.circom";

template ZkLoginSha256(maxHeaderLen, maxPaddedUnsignedJWTLen){
  var inCount = maxPaddedUnsignedJWTLen;

  var maxSubLen = 255;
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

  signal input padded_unsigned_jwt[maxPaddedUnsignedJWTLen];
  signal input payload_start_index;
  signal input payload_len;
  signal input num_sha2_blocks;

  signal input signature[32];
  signal input pubkey[32];
  signal input salt[16]; // public

  signal input sub_claim[maxSubClaimLen];
  signal input sub_claim_length;
  signal input sub_index_b64;
  signal input sub_length_b64;
  signal input sub_name_length; // with quotes
  signal input sub_colon_index;
  signal input sub_value_index;
  signal input sub_value_length; // with quotes

  signal input nonce_claim[maxNonceClaimLen];
  signal input nonce_claim_length;
  signal input nonce_index_b64;
  signal input nonce_length_b64;
  signal input nonce_name_length; // with quotes
  signal input nonce_colon_index;
  signal input nonce_value_index;
  signal input nonce_value_length;

  signal output id_hash[32];

  // component VERIFYJWT = JWTVerify(maxJwtLen, 121, 17);
  component VerifyJwt = JWTVerifyNew(maxHeaderLen, maxPaddedUnsignedJWTLen);

  VerifyJwt.padded_unsigned_jwt <== padded_unsigned_jwt;
  VerifyJwt.payload_start_index <== payload_start_index;
  VerifyJwt.num_sha2_blocks <== num_sha2_blocks;
  VerifyJwt.payload_len <== payload_len;
  VerifyJwt.signature <== signature;
  VerifyJwt.modulus <== pubkey;

  // Extract nonce claim

  signal nonce_value_with_quotes[maxNonceValueLen];
  component NonceExtClaimOps = ExtClaimOps(inCount, maxNonceClaimLen, maxNonceNameLen, maxNonceValueLen, maxWhiteSpaceLen);
  NonceExtClaimOps.content <== padded_unsigned_jwt;
  NonceExtClaimOps.index_b64 <== nonce_index_b64;
  NonceExtClaimOps.length_b64 <== nonce_length_b64;

  NonceExtClaimOps.ext_claim <== nonce_claim;
  NonceExtClaimOps.ext_claim_length <== nonce_claim_length;
  NonceExtClaimOps.name_length <== nonce_name_length; // with quotes
  NonceExtClaimOps.colon_index <== nonce_colon_index;
  NonceExtClaimOps.value_index <== nonce_value_index;
  NonceExtClaimOps.value_length <== nonce_value_length; // with quotes
  NonceExtClaimOps.payload_start_index <== payload_start_index;


  NonceExtClaimOps.claim_name === [34, 110, 111, 110, 99, 101, 34]; // '"nonce"'
  nonce_value_with_quotes <== NonceExtClaimOps.claim_value;


  signal output nonce[maxNonceLen] <== QuoteRemover(maxNonceValueLen)(
      nonce_value_with_quotes, nonce_value_length
  );

  // Extract sub claim
  signal sub_value_with_quotes[maxSubValueLen];
  component SubExtClaimOps = ExtClaimOps(inCount, maxSubClaimLen, maxSubNameLen, maxSubValueLen, maxWhiteSpaceLen);
  SubExtClaimOps.content <== padded_unsigned_jwt;
  SubExtClaimOps.index_b64 <== sub_index_b64;
  SubExtClaimOps.length_b64 <== sub_length_b64;

  SubExtClaimOps.ext_claim <== sub_claim;
  SubExtClaimOps.ext_claim_length <== sub_claim_length;
  SubExtClaimOps.name_length <== sub_name_length; // with quotes
  SubExtClaimOps.colon_index <== sub_colon_index;
  SubExtClaimOps.value_index <== sub_value_index;
  SubExtClaimOps.value_length <== sub_value_length; // with quotes
  SubExtClaimOps.payload_start_index <== payload_start_index;


  SubExtClaimOps.claim_name === [34, 115, 117, 98, 34]; // '"sub"'
  sub_value_with_quotes <== SubExtClaimOps.claim_value;

  signal sub[maxSubLen] <== QuoteRemover(maxSubValueLen)(
      sub_value_with_quotes, sub_value_length
  );

  component CalculateIdHash = IdHashSha256(maxSubLen, 16);
  CalculateIdHash.sub <== sub;
  CalculateIdHash.sub_len <== sub_value_length - 2;
  CalculateIdHash.salt <== salt;
  CalculateIdHash.salt_len <== 16;

  id_hash <== CalculateIdHash.out;
}

component main {public [pubkey, salt]} = ZkLoginSha256(256, 1024);
