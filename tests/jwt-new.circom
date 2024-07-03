
pragma circom 2.1.5;

include "../circuits/helpers/jwt-new.circom";

component main = JWTVerifyNew(256, 1024);