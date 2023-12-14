pragma circom 2.1.5;

include "../circuits/helpers/jwt-sub-extract.circom";

component main { public [ jwt ] } = ExtractSubFromJWT(512, 256);