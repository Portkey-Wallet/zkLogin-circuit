// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

pragma circom 2.1.5;

include "../circuits/helpers/sha256.circom";

include "../circuits/helpers/guardian-identifier-hash.circom";

component main { public [in_padded, in_len_padded_bytes] } = Sha256BytesOutputBytes(640);