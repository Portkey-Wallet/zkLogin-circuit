// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

pragma circom 2.1.5;

include "../circuits/helpers/string.circom";

component main { public [ text, startIndex, count ] } = SubString(256, 64);