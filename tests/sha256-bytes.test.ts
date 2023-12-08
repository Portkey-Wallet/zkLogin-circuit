import path from "path";
import { wasm } from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { Uint8ArrayToCharArray, hexToBytes, padString, sha256Pad, shaHash, uint8ToBits } from "../utils";
import { sha256 } from "js-sha256";
import { padBytes } from "../utils/pad-bytes";
let encoder = new TextEncoder();

describe("Sha256Bytes test", function () {
  let circuit;

  describe("Hash should be correct", () => {
    beforeAll(async () => {
      circuit = await wasm(
        path.join(__dirname, "./sha256-bytes-test.circom"),
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
      const [paddedMsg, messageLen] = sha256Pad(bytes, 256);
      const witness = await circuit.calculateWitness({
        in_len_padded_bytes: messageLen,
        in_padded: Uint8ArrayToCharArray(paddedMsg),
      });

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        out: [...shaHash(bytes)],
      });
    });
  });
});
