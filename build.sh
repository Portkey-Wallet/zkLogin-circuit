# generate the circuit r1cs and wtns
circom circuits/guardianhash.circom --r1cs --sym --wasm -l node_modules -o out
npx tsx src/generate-input.ts
cd out/guardianhash_js
cat input.json
node generate_witness.js guardianhash.wasm input.json ../witness.wtns

# cd into ceremony/bls12381 and refer to the build.sh there to continue