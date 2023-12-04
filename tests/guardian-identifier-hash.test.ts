import path from "path";
import { wasm } from "circom_tester";
import { describe, it } from "vitest";
import { padString } from "../utils";

describe("Guardian Identifier test", function () {
  it("Checking the guardian identifier", async function () {
    const circuit = await wasm(
      path.join(__dirname, "./guardian-identifier-hash-test.circom"),
      {
        // @dev During development recompile can be set to false if you are only making changes in the tests.
        // This will save time by not recompiling the circuit every time.
        // Compile: circom "./tests/email-verifier-test.circom" --r1cs --wasm --sym --c --wat --output "./tests/compiled-test-circuit"
        recompile: true,
        output: path.join(__dirname, "./compiled-test-circuit"),
        include: path.join(__dirname, "../node_modules"),
      }
    );

    const sub = padString("116111375152810828167", 512);
    const salt = padString("a677999396dc49a28ad6c9c242719bb3", 512);

    const w = await circuit.calculateWitness(
      {
        sub,
        salt,
      },
      true
    );
    await circuit.checkConstraints(w);
  });
});
