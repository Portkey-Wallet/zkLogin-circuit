import path from "path";
import { wasm } from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { padString, uint8ToBits, shaHash } from "../utils";
let encoder = new TextEncoder();

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
      const input = "01";
      const padText = padString(input, 256);
      const witness = await circuit.calculateWitness({
        sub: padText,
      });

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        sha: [...uint8ToBits(shaHash(encoder.encode(input)))],
      });
    });
  });
});
