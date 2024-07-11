// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

pragma circom 2.1.5;

include "../../../circuits/helpers/sha256.circom";

component main { public [text] } = Sha256Pad(640);