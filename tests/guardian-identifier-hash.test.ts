import path from "path";
import { wasm } from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { padString, uint8ToBits, shaHash } from "../utils";

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

    it("should hash correctly", async function () {
      let encoder = new TextEncoder();
      const inputs = ["01"];
      for (const [input] of inputs) {
        const padText = padString(input, 256);
        const witness = await circuit.calculateWitness({
          sub: padText,
        });

        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {
          sha: [...uint8ToBits(shaHash(encoder.encode(input)))],
        });
      }
    });
  });

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

    it("should hash correctly", async function () {
      let encoder = new TextEncoder();
      const inputs = [
        {
          hash1: padString(shaHash(encoder.encode("01")).toString("hex"), 256),
          salt: padString("6489b951119243958d720c41a810f448", 64),
        },
      ];
      for (const { hash1, salt } of inputs) {
        const witness = await circuit.calculateWitness({
          hash1,
          salt,
        });

        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {
          sha: [
            ...uint8ToBits(
              shaHash(Buffer.concat([Buffer.from(salt), Buffer.from(hash1)]))
            ),
          ],
        });
      }
    });
  });
});
