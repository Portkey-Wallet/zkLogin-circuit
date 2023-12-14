pragma circom 2.0.0;
include "./jwt.circom";
include "./base64.circom";

template ExtractSubFromJWT(){
  signal input jwt[512];
  signal output out[256];

  component SPLITJWT = JWTSplit(512);
  component DECODE = Base64Decode(128);
  component SUBSTR = SubString(512, 256);

  // split the jwt so that we can extract the sub
  SPLITJWT.jwt <== jwt;
  DECODE.in <== SPLITJWT.payload;
  SUBSTR.text <== DECODE.out;
  SUBSTR.startIndex <== 8;
  SUBSTR.count <== 18; // WIP: need a way to get the length of the sub

  out <== SUBSTR.substring;
}