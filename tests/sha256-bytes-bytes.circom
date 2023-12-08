// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

pragma circom 2.1.5;

include "../circuits/helpers/sha256.circom";

include "../circuits/helpers/guardian-identifier-hash.circom";

template Sha256BytesOutputBytes(max_num_bytes) {
    signal input in_padded[max_num_bytes];
    signal input in_len_padded_bytes;
    signal output out[32];
    component SHA256BYTES = Sha256Bytes(max_num_bytes);
    SHA256BYTES.in_padded <== in_padded;
    SHA256BYTES.in_len_padded_bytes <== in_len_padded_bytes;
    component B2B = BitsToBytes(256);
    B2B.in <== SHA256BYTES.out;
    out <-- B2B.out;
}

component main { public [in_padded, in_len_padded_bytes] } = Sha256BytesOutputBytes(640);