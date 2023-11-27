circom circuits/sha256.circom --r1cs --wasm --sym --c -o ./out
cd out/sha256_js
echo '{"sub":["1","1","6","1","1","1","3","7","5","1","5","2","8","1","0","8","2","8","1","6","7"]}' > input.json
node generate_witness.js sha256.wasm input.json witness.wtns
cd ../../