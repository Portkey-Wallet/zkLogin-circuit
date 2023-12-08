import path from "path";
import { wasm } from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import {
  uint8ToBits,
  shaHash,
  sha256Pad,
  Uint8ArrayToCharArray,
} from "../utils";
import { hexToBytes } from "../utils";

describe("Guardian Identifier test", function () {
  let circuit;

  describe("Hash1 should be correct", () => {
    beforeAll(async () => {
      circuit = await wasm(
        path.join(__dirname, "./guardian-identifier-hash1.circom"),
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

    it("should hash1 correctly", async function () {
      const input = hexToBytes(
        "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
      );
      const [paddedMsg, messageLen] = sha256Pad(input, 512);

      const witness = await circuit.calculateWitness({
        in_len_padded_bytes: messageLen,
        in_padded: Uint8ArrayToCharArray(paddedMsg),
      });

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        out: [...uint8ToBits(shaHash(input))],
      });
    });
  });
});
