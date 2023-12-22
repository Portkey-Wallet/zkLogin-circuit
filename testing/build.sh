circom ../circuits/testing.circom --r1cs --sym --json --wasm -l ../node_modules -o .
cp ./testing_js/* .
rm -rf testing_js
node generate_witness.js testing.wasm input.json witness.wtns
snarkjs powersoftau new bn128 7 pot_0000.ptau -v
snarkjs powersoftau contribute pot_0000.ptau pot_0001.ptau --name="First contribution" -v
snarkjs powersoftau prepare phase2 pot_0001.ptau pot_final.ptau -v
snarkjs groth16 setup testing.r1cs pot_final.ptau testing_0000.zkey
snarkjs zkey contribute testing_0000.zkey testing_0001.zkey --name="1st Contributor Name" -v
snarkjs zkey export verificationkey testing_0001.zkey verification_key.json
snarkjs groth16 prove testing_0001.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json