// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

pragma circom 2.1.5;

include "./sha256-new.circom";
include "./rsa-new.circom";

template JWTVerifyNew(maxHeaderLen, maxPaddedUnsignedJWTLen) {
    var inWidth = 8; // in bytes
    var inCount = maxPaddedUnsignedJWTLen;
    /**
     1. Parse out the JWT header 
    **/
    signal input padded_unsigned_jwt[inCount];
    signal input payload_start_index;

    // Extract the header
    var header_length = payload_start_index - 1;
    signal header[maxHeaderLen] <== SliceFromStart(inCount, maxHeaderLen)(
        padded_unsigned_jwt, header_length
    );

    // Check that there is a dot after header
    var x = SingleMultiplexer(inCount)(padded_unsigned_jwt, header_length);
    x === 46; // 46 is the ASCII code for '.'

    /**
     2. SHA2 operations over padded_unsigned_jwt
        - Check the validity of SHA2 padding
        - Compute SHA2(padded_unsigned_jwt)
    */
    signal input num_sha2_blocks;
    signal input payload_len;

    // Check the validity of the SHA2 padding
    var padded_unsigned_jwt_len = 64 * num_sha2_blocks; // 64 bytes per SHA2 block
    var sha2pad_index = payload_start_index + payload_len;

    SHA2PadVerifier(inCount)(padded_unsigned_jwt, padded_unsigned_jwt_len, sha2pad_index);

    var hashCount = 4;
    var hashWidth = 256 / hashCount;
    signal jwt_sha2_hash[hashCount] <== Sha2_wrapper(inWidth, inCount, hashWidth, hashCount)(
        padded_unsigned_jwt, num_sha2_blocks
    );

    /**
     3. Check signature
    **/
    signal input signature[32]; // The JWT signature  
    signal input modulus[32];
    var jwt_sha2_hash_le[4]; // converting to little endian
    for (var i = 0; i < 4; i++) {
        jwt_sha2_hash_le[i] = jwt_sha2_hash[3 - i];
    }
    RSAVerify65537()(signature, modulus, jwt_sha2_hash_le);
}

