// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

pragma circom 2.1.5;

include "../../../circuits/helpers/jwtchecks.circom";

component main { public [content, index_b64, length_b64, ext_claim, ext_claim_length, name_length, colon_index, value_index, value_length, payload_start_index] } = ExtClaimOps(2048, 256, 10, 256, 0);

///,"sub":"110117207114221115868",
