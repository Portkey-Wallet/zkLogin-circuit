import path from "path";
import { wasm } from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { padString, uint8ToBits, shaHash } from "../utils";
import { sha256 } from "js-sha256";
let encoder = new TextEncoder();

describe("Guardian Identifier test", function () {
  let circuit;

  describe("Hash2 should be correct", () => {
    beforeAll(async () => {
      circuit = await wasm(
        path.join(__dirname, "./guardian-identifier-hash2.circom"),
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

    it("should hash2 correctly", async function () {
      const hash1 = sha256("01");
      const salt = "75f8c36b93874977b47bb92a3f7c1536";
      const witness = await circuit.calculateWitness({
        hash1: padString(hash1, 256),
        salt: padString(salt, 128),
      });

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        sha: [...uint8ToBits(shaHash(encoder.encode(salt + hash1)))],
      });
    });
  });
});
