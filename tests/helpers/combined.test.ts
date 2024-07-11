import path from "path";
import { wasm } from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import {
  uint8ToBits,
  shaHash,
  sha256Pad,
  Uint8ArrayToCharArray,
} from "../../utils";
import { hexToBytes } from "../../utils";

describe("Bytes concatenation test", function () {
  let circuit;

  describe("Bytes concatenation test", () => {
    beforeAll(async () => {
      circuit = await wasm(path.join(__dirname, "./circuits/combined.circom"), {
        // @dev During development recompile can be set to false if you are only making changes in the tests.
        // This will save time by not recompiling the circuit every time.
        // Compile: circom "./tests/email-verifier-test.circom" --r1cs --wasm --sym --c --wat --output "./tests/compiled-test-circuit"
        recompile: true,
        output: path.join(__dirname, "./compiled-test-circuit"),
        include: path.join(__dirname, "../../node_modules"),
      });
    });

    it("should combine correctly", async function () {
      const hash =
        "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a";
      const salt = "8a7e44fa4a244e28a65ed89962997c41";
      const combined = hash + salt;

      const witness = await circuit.calculateWitness({
        first: Uint8ArrayToCharArray(hexToBytes(hash)),
        second: Uint8ArrayToCharArray(hexToBytes(salt)),
      });

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        out: [...hexToBytes(combined)],
      });
    });
  });
});
