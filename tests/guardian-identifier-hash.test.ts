import path from "path";
import { wasm } from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { hexToBytes, padString, shaHash, uint8ToBits } from "../utils";
import { sha256 } from "js-sha256";
import { padBytes } from "../utils/pad-bytes";
let encoder = new TextEncoder();

describe("Guardian Identifier test", function () {
  let circuit;

  describe("Hash should be correct", () => {
    beforeAll(async () => {
      circuit = await wasm(
        path.join(__dirname, "./guardian-identifier-hash.circom"),
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
      const sub = hexToBytes("01");
      const salt = hexToBytes("8a7e44fa4a244e28a65ed89962997c41");

      const witness = await circuit.calculateWitness({
        sub: padBytes(sub, 256),
        sub_len: sub.length,
        salt: padBytes(salt, 32),
        salt_len: salt.length
      });

      console.log([
          hexToBytes(
            "ac379499210dc4af65b537bd5deed7033d664cb2b55965105e8ad68fadb13456"
        ),
      ]);

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        out: [
          ...hexToBytes(
            "ac379499210dc4af65b537bd5deed7033d664cb2b55965105e8ad68fadb13456"
          ),
        ],
      });
    });
  });
});
