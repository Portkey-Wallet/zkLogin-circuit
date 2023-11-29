// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

pragma circom 2.1.5;

include "../circuits/helpers/jwt.circom";

component main { public [ jwt ] } = JWTSplit(512);