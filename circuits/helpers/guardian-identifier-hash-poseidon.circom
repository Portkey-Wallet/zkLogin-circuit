pragma circom 2.0.0;
include "./hashtofield.circom";

template IdentifierHashByPoseidon(sub_bytes, salt_bytes){
  signal input sub[sub_bytes];
  signal input salt[salt_bytes];

  var sub_F, salt_F;

  sub_F = HashBytesToField(sub_bytes)(sub);
  salt_F = ChunksToFieldElem(salt_bytes, 8)(salt);
  signal output out <== HashElemsToField(2)([
    sub_F, salt_F
  ]);
}
