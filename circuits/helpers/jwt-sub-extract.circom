pragma circom 2.0.0;
include "./base64.circom";

template JWTSplit(max_bytes) {
  signal input jwt[max_bytes];
  signal output header[max_bytes];
  signal output payload[max_bytes];
  signal output signature[max_bytes];

  // split JWT 
  component splitedJWT = SplitBy(max_bytes, 46, 3); // 46 is '.'

  splitedJWT.text <== jwt;
  header <== splitedJWT.out[0];
  payload <== splitedJWT.out[1];
  signature <== splitedJWT.out[2];
}

template ExtractSubFromJWT(jwt_max, sub_max){
  signal input jwt[jwt_max];
  signal output sub[sub_max];
  signal output sub_len;

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
  var SUB_LEN = INDEXOF.index - 8;
  SUBSTR.count <== SUB_LEN; // index of the closing '"' minus the start index equals length of sub

  sub <== SUBSTR.substring;
  sub_len <== SUB_LEN;
}