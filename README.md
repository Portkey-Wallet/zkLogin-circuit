# Portkey zkLogin Circuits

[![Test](https://github.com/Portkey-Wallet/zkLogin-circuit/actions/workflows/test.yml/badge.svg)](https://github.com/Portkey-Wallet/zkLogin-circuit/actions/workflows/test.yml)

This repo contains 3 circuits:

| Circuit Name | Description |
|--------------|-------------|
|[zkLogin](./circuits/zkLogin.circom)|The main zkLogin circuit which verifies jwt token, checks claims such as `sub` and `nonce`, and generates an `id` based on `sub` and `salt` using Poseidon hash function.|
|[zkLoginSha256](./circuits/zkLoginSha256.circom)|This circuit is similar to `zkLogin` except that it uses Sha256 hash function instead of Poseidon|
|[idHashMapping](./circuits/idHashMapping.circom)|This circuit is used for backward compatibility. Portkey has existing accounts that derive `id` using Sha256. However going forward if we use Poseidon, we need to know the corresponding `id`. This circuit provides a mapping between these two `id`s without revealing user's `sub`.|


## Test

1. Install dependencies

```
npm install
```

2. Run tests

```
npm run test
```

## Notes
To use the circuits, we need to run the [Groth16 Trusted Setup](https://zkproof.org/2021/06/30/setup-ceremonies/) to create the `zkey` and use a service to prepare the input in the format expected by the circuits. Our corresponding proving service is hosted in [this repo](https://github.com/Portkey-Wallet/ProvingService).
