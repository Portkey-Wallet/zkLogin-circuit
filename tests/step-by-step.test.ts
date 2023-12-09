import path from "path";
import { wasm } from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { Uint8ArrayToCharArray, hexToBytes, padString, sha256Pad, shaHash, uint8ToBits } from "../utils";
import { sha256 } from "js-sha256";
import { padBytes } from "../utils/pad-bytes";
let encoder = new TextEncoder();

function concatenateUint8Arrays(arrays) {
  // Calculate the total length of the concatenated array
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);

  // Create a new Uint8Array with the total length
  const result = new Uint8Array(totalLength);

  // Use a variable to keep track of the current position in the result array
  let position = 0;

  // Iterate over each input array and copy its elements to the result array
  arrays.forEach(arr => {
    result.set(arr, position);
    position += arr.length;
  });

  return result;
}


describe("Hash test", function () {
  let circuit;

  describe("Hash should be correct", () => {
    beforeAll(async () => {
      circuit = await wasm(
        path.join(__dirname, "./step-by-step-1-hash.circom"),
        {
          // @dev During development recompile can be set to false if you are only making changes in the tests.
          // This will save time by not recompiling the circuit every time.
          // Compile: circom "./tests/email-verifier-test.circom" --r1cs --wasm --sym --c --wat --output "./tests/compiled-test-circuit"
          recompile: true,
          output: path.join(__dirname, "./compiled-test-circuit"),
          include: path.join(__dirname, "../node_modules"),
        }
      );
    });

    it("should hash correctly", async function () {
      const sub = hexToBytes("01");

      const witness = await circuit.calculateWitness({
        sub: padBytes(sub, 256),
        sub_len: sub.length
      });

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        out: [
          ...hexToBytes(
            "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"
          )
        ],
      });
    });
  });
});

describe("Hash and combine test", function () {
  let circuit;

  describe("Hash should be correct", () => {
    beforeAll(async () => {
      circuit = await wasm(
        path.join(__dirname, "./step-by-step-2-hash-and-combine.circom"),
        {
          // @dev During development recompile can be set to false if you are only making changes in the tests.
          // This will save time by not recompiling the circuit every time.
          // Compile: circom "./tests/email-verifier-test.circom" --r1cs --wasm --sym --c --wat --output "./tests/compiled-test-circuit"
          recompile: true,
          output: path.join(__dirname, "./compiled-test-circuit"),
          include: path.join(__dirname, "../node_modules"),
        }
      );
    });

    it("should hash correctly", async function () {
      const sub = hexToBytes("01");
      const salt = hexToBytes("8a7e44fa4a244e28a65ed89962997c41");

      const witness = await circuit.calculateWitness({
        sub: padBytes(sub, 256),
        sub_len: sub.length,
        salt: padBytes(salt, 32),
      });

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        out: [
          ...hexToBytes(
            "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"+"8a7e44fa4a244e28a65ed89962997c41"
          ),
        ],
      });
    });
  });
});
