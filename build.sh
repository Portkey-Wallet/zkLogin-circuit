circom circuits/guardianhash.circom --r1cs --sym --wasm -l node_modules -o out
npx ts-node src/generate-input.ts
cd out/guardianhash_js
node generate_witness.js guardianhash.wasm input.json ../witness.wtns
cd ..
snarkjs powersoftau new bn128 20 pot_0000.ptau -v
snarkjs powersoftau contribute pot_0000.ptau pot_0001.ptau --name="First contribution" -v
snarkjs powersoftau prepare phase2 pot_0001.ptau pot_final.ptau -v
snarkjs groth16 setup guardianhash.r1cs pot_final.ptau guardianhash_0000.zkey
snarkjs zkey contribute guardianhash_0000.zkey guardianhash_0001.zkey --name="1st Contributor Name" -v
snarkjs zkey export verificationkey guardianhash_0001.zkey verification_key.json
snarkjs groth16 prove guardianhash_0001.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json