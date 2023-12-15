# example-circuit

## Install

Run `npm install` at the terminal.

## Build circuit

```bash
circom circuits/guardianhash.circom --r1cs --sym --json --wasm -l node_modules -o bls12381 --prime bls12381
```

The output files will be at `bls12381` folder.

## Test circuit

Run `npm test` at the terminal.

## Prepare the input.json for generating the witness

Run `npm run generateinput` and follow the prompts. Press enter for the defaults.

## Generate the witness

```bash
cd bls12381/guardianhash_js
node generate_witness.js guardianhash.wasm ../input.json ../witness.wtns
```

## Ceremony

### Phase 1

```bash
cd bls12381
snarkjs powersoftau new bls12381 20 pot20_0000.ptau -v
snarkjs powersoftau contribute pot20_0000.ptau pot20_0001.ptau --name="First contribution" -v
snarkjs powersoftau prepare phase2 pot20_0001.ptau pot20_final.ptau -v
```

### Phase 2

```bash
cd bls12381
snarkjs groth16 setup guardianhash.r1cs pot20_final.ptau guardianhash_0000.zkey
snarkjs zkey contribute guardianhash_0000.zkey guardianhash_0001.zkey --name="1st Contributor Name" -v
snarkjs zkey export verificationkey guardianhash_0001.zkey verification_key.json
```

## Proof generation

```bash
cd bls12381
snarkjs groth16 prove guardianhash_0001.zkey witness.wtns proof.json public.json
```

## Verify

```bash
cd bls12381
snarkjs groth16 verify verification_key.json public.json proof.json
```
