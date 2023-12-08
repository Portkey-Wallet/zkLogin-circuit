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

describe("Sha256Bytes test", function () {
  let circuit;

  describe("Hash should be correct", () => {
    beforeAll(async () => {
      circuit = await wasm(
        path.join(__dirname, "./sha256-bytes-bytes.circom"),
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
      const bytes = hexToBytes("01");
      const hash = hexToBytes("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a");
      const [paddedMsg, messageLen] = sha256Pad(bytes, 640);
      const witness = await circuit.calculateWitness({
        in_len_padded_bytes: messageLen,
        in_padded: Uint8ArrayToCharArray(paddedMsg),
      });

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        out: [...hash],
      });
    });
  });

  describe("Sha256PadBytes", () => {
    beforeAll(async () => {
      circuit = await wasm(
        path.join(__dirname, "./sha256-pad-bytes-bytes.circom"),
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

    it("should sha256Pad correctly", async function () {
      const hash = hexToBytes("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a");
      const salt = hexToBytes("8a7e44fa4a244e28a65ed89962997c41");
      const combined = concatenateUint8Arrays([hash, salt]);
      
      const [paddedMsg, messageLen] = sha256Pad(combined, 640);

      const witness = await circuit.calculateWitness({
        in_bytes: combined.length,
        in: padBytes(combined, 640),
      });

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        padded_len: messageLen,
        padded_text: Array.from(paddedMsg),
      });
    });
  });

  describe("Hash2 should be correct", () => {
    beforeAll(async () => {
      circuit = await wasm(
        path.join(__dirname, "./sha256-bytes-bytes.circom"),
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
      
      const hash1 = hexToBytes("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a");
      const salt = hexToBytes("8a7e44fa4a244e28a65ed89962997c41");
      const combined = concatenateUint8Arrays([hash1, salt]);
      const hash2 = hexToBytes("ac379499210dc4af65b537bd5deed7033d664cb2b55965105e8ad68fadb13456");

      const [paddedMsg, messageLen] = sha256Pad(combined, 640);
  
      const witness = await circuit.calculateWitness({
        in_len_padded_bytes: messageLen,
        in_padded: Uint8ArrayToCharArray(paddedMsg),
      });

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        out: [...hash2],
      });
    });
  });
});


