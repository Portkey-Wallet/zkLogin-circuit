# compile the circuit
mkdir -p out
circom ../circuits/guardianhash.circom --r1cs --wasm --sym --c -l ../node_modules -o ./out

# compute the witness
# node ./out/guardianhash_js/generate_witness.js ./out/guardianhash_js/guardianhash.wasm input.json witness.wtns

# ceremony
