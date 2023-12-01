// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

pragma circom 2.1.5;

include "../circuits/helpers/guardian-identifier-hash.circom";

component main { public [ sub, salt ] } = GuardianIdentifierHash(512, 512);