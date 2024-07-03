pragma circom 2.0.0;
include "./helpers/guardian-identifier-hash.circom";
include "./helpers/guardian-identifier-hash-poseidon.circom";
include "./helpers/base64.circom";
include "./helpers/jwt-sub-extract.circom";
include "./helpers/jwtchecks.circom";

template Sha256ToPoseidonMapping(maxSubLen, maxSaltLen){
    signal input sub[maxSubLen];
    signal input subLen;
    signal input salt[maxSaltLen];
    signal input saltLen;
    component poseidonHasher = IdentifierHashByPoseidon(maxSubLen, maxSaltLen);

    poseidonHasher.sub <== sub;
    poseidonHasher.salt <== salt;

    component sha256Hasher = GuardianIdentifierHash(maxSubLen, 16);

    sha256Hasher.sub <== sub;
    sha256Hasher.sub_len <== subLen;
    sha256Hasher.salt <== salt;
    sha256Hasher.salt_len <== 16;

    signal output poseidon_hash <== poseidonHasher.out;
    signal output sha256_hash[32] <== sha256Hasher.out;
}

component main = Sha256ToPoseidonMapping(255, 16);
