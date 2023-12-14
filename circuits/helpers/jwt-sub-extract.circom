pragma circom 2.0.0;
include "./jwt.circom";
include "./base64.circom";

template ExtractSubFromJWT(jwt_max, sub_max){
  signal input jwt[jwt_max];
  signal output sub[sub_max];

  component SPLITJWT = JWTSplit(jwt_max);
  component DECODE = Base64Decode(jwt_max);
  component SUBSTR = SubString(jwt_max, sub_max);
  component INDEXOF = IndexOf(jwt_max);

  // split the jwt so that we can extract the sub
  SPLITJWT.jwt <== jwt;
  DECODE.in <== SPLITJWT.payload;
  SUBSTR.text <== DECODE.out;

  // find out the length of the sub
  INDEXOF.text <== DECODE.out;
  INDEXOF.startIndex <== 8;  // we want to get the first '"' character after this index
  INDEXOF.targetChar <== 34; // the char code of the '"' character
  
  SUBSTR.startIndex <== 8;
  SUBSTR.count <== INDEXOF.index - 8; // index of the closing '"' minus the start index equals length of sub

  sub <== SUBSTR.substring;
}