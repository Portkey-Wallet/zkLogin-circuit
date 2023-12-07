pragma circom 2.1.5;

include "../circuits/helpers/guardian-identifier-hash.circom";

component main { public [sub] } = Hash1(256);