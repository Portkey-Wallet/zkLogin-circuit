// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

pragma circom 2.1.5;

include "circomlib/circuits/bitify.circom";
include "./misc.circom";
include "./utils.circom";
include "./sha256general.circom";
include "./sha256partial.circom";
include "./sha256-new.circom";

template Sha256PadAndHash(max_bytes){
  signal input in[max_bytes];
  signal input in_len;
  signal output out[32];

  var max_padded_len = (max_bytes + 9) + (64 - (max_bytes + 9) % 64);
  signal padded_in[max_padded_len];
  for (var i = 0; i < max_padded_len; i++) {
    padded_in[i] <== i < max_bytes ? in[i] : 0;
  }

  component sha256Pad = Sha256PadBytes(max_padded_len);
  sha256Pad.in <== SliceFromStart(max_padded_len, max_padded_len)(padded_in, in_len);
  sha256Pad.in_bytes <== in_len;

  component sha256BB = Sha256BytesOutputBytes(max_padded_len);
  
  sha256BB.in_padded <== sha256Pad.padded_text;
  sha256BB.in_len_padded_bytes <== sha256Pad.padded_len;
  out <== sha256BB.out;
}

template Sha256BytesOutputBytes(max_num_bytes) {
    signal input in_padded[max_num_bytes];
    signal input in_len_padded_bytes;
    signal output out[32];
    component SHA256BYTES = Sha256Bytes(max_num_bytes);
    SHA256BYTES.in_padded <== in_padded;
    SHA256BYTES.in_len_padded_bytes <== in_len_padded_bytes;
    component B2B = BitsToBytes(256);
    B2B.in <== SHA256BYTES.out;
    out <== B2B.out;
}

template Sha256Bytes(max_num_bytes) {
    signal input in_padded[max_num_bytes];
    signal input in_len_padded_bytes;
    signal output out[256];

    var num_bits = max_num_bytes * 8;
    component sha = Sha256General(num_bits);

    component bytes[max_num_bytes];
    for (var i = 0; i < max_num_bytes; i++) {
        bytes[i] = Num2Bits(8);
        bytes[i].in <== in_padded[i];
        for (var j = 0; j < 8; j++) {
            sha.paddedIn[i*8+j] <== bytes[i].out[7-j];
        }
    }
    sha.in_len_padded_bits <== in_len_padded_bytes * 8;

    for (var i = 0; i < 256; i++) {
        out[i] <== sha.out[i];
    }
}

template Sha256PadBytes(max_bytes) {
    signal input in[max_bytes];
    signal input in_bytes;
    signal output padded_text[max_bytes];
    signal output padded_len;
    assert(in_bytes > 0);

    // in_bytes + 1 bytes + 8 bytes length < max_bytes
    assert(in_bytes + 9 < max_bytes);

    var padding_len = (in_bytes + 9) == 64 ? 0 : 64 - (in_bytes + 9) % 64;

    padded_len <-- (in_bytes + 9) + padding_len;
    assert(padded_len % 64 == 0);

    component len2bytes = Packed2BytesBigEndian(8);
    len2bytes.in <== in_bytes * 8;

    for (var i = 0; i < max_bytes; i++) {
        padded_text[i] <-- i < in_bytes ? in[i] : (i == in_bytes ? (1 << 7) : ((i < padded_len && i >= padded_len - 8) ? len2bytes.out[(i % 64 - 56)]: 0)); // Add the 1 on the end and text length
    }

    signal enabled[max_bytes] <== LTBitVector(max_bytes)(in_bytes);
    for (var i = 0; i < max_bytes; i++) {
        AssertEqualIfEnabled()(enabled[i], [padded_text[i], in[i]]);
    }
    SHA2PadVerifier(max_bytes)(padded_text, padded_len, in_bytes);
}
