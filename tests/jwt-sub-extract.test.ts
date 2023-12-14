import path from "path";
import { wasm as wasm_tester } from "circom_tester";
import { padString } from "../utils";
import { describe, beforeAll, it } from "vitest";

describe("JWT Sub Extract", () => {
  let circuit: any;

  beforeAll(async () => {
    circuit = await wasm_tester(
      path.join(__dirname, "./jwt-sub-extract-test.circom"),
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

  it("should be able to extract sub from jwt", async function () {
    const inputs = [
      [
        padString(
          "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
          512
        ),
        padString("1234567890", 256),
        10,
      ],
    ];

    for (const [jwt, sub, sub_len] of inputs) {
      const witness = await circuit.calculateWitness({
        jwt,
      });
      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, { sub, sub_len });
    }
  });
});
