import path from "path";
import { wasm } from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { hexToBytes, uint8ToBits } from "../../utils";

describe("Bits to bytes conversion test", function () {
  let circuit;

  describe("Bits to bytes conversion", () => {
    beforeAll(async () => {
      circuit = await wasm(
        path.join(__dirname, "./circuits/bits-to-bytes.circom"),
        {
          // @dev During development recompile can be set to false if you are only making changes in the tests.
          // This will save time by not recompiling the circuit every time.
          // Compile: circom "./tests/email-verifier-test.circom" --r1cs --wasm --sym --c --wat --output "./tests/compiled-test-circuit"
          recompile: true,
          output: path.join(__dirname, "./compiled-test-circuit"),
          include: path.join(__dirname, "../../node_modules"),
        }
      );
    });

    it("should convert bits to bytes correctly", async function () {
      const bytes = hexToBytes("ac379499210dc4af65b537bd5deed7033d664cb2b55965105e8ad68fadb13456");
      const witness = await circuit.calculateWitness({
        in: [...uint8ToBits(bytes)]
      });

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        out: [...bytes],
      });
    });
  });
});
