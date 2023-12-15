# ceremony phase 1
snarkjs powersoftau new bls12381 20 pot20_0000.ptau -v
snarkjs powersoftau contribute pot20_0000.ptau pot20_0001.ptau --name="First contribution" -v
snarkjs powersoftau prepare phase2 pot20_0001.ptau pot20_final.ptau -v

# assuming the circuit has been compiled in out (refer to build.sh in project root)
cp ../../out/*.{r1cs,wtns} .

# ceremony phase 2
snarkjs groth16 setup guardianhash.r1cs pot20_final.ptau guardianhash_0000.zkey
snarkjs zkey contribute guardianhash_0000.zkey guardianhash_0001.zkey --name="1st Contributor Name" -v
snarkjs zkey export verificationkey guardianhash_0001.zkey verification_key.json

# generate proof
snarkjs groth16 prove guardianhash_0001.zkey witness.wtns proof.json public.json
cat public.json
cat proof.json

# verify
snarkjs groth16 verify verification_key.json public.json proof.json