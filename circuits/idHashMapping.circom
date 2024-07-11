pragma circom 2.0.0;
include "./helpers/idhash_sha256.circom";
include "./helpers/idhash_poseidon.circom";
include "./helpers/jwtchecks.circom";

template IdHashMapping(maxSubLen, maxSaltLen){
    signal input sub[maxSubLen];
    signal input subLen;
    signal input salt[maxSaltLen];
    signal input saltLen;
    component poseidonHasher = IdHashPoseidon(maxSubLen, maxSaltLen);

    poseidonHasher.sub <== sub;
    poseidonHasher.salt <== salt;

    component sha256Hasher = IdHashSha256(maxSubLen, 16);

    sha256Hasher.sub <== sub;
    sha256Hasher.sub_len <== subLen;
    sha256Hasher.salt <== salt;
    sha256Hasher.salt_len <== 16;

    signal output poseidon_hash <== poseidonHasher.out;
    signal output sha256_hash[32] <== sha256Hasher.out;
}

component main = IdHashMapping(255, 16);
