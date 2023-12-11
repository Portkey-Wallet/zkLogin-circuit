// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

import { wasm as wasm_tester } from "circom_tester";
import path from "path";
import { padString } from "../utils";
import { describe, beforeAll, it } from "vitest";

describe("Substring Test", () => {
  let circuit: any;

  describe("SubString", () => {
    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "./string-substring-test.circom"),
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

    it("should SubString be ok", async function () {
      const inputs = [
        [padString("ABCDEFG", 256), 0, 3, padString("ABC", 64)],
        [padString("ABCDEFG", 256), 1, 3, padString("BCD", 64)],
        [padString("ABC.ABC.ABC", 256), 0, 3, padString("ABC", 64)],
      ];

      for (const [text, startIndex, count, output] of inputs) {
        const witness = await circuit.calculateWitness({
          text,
          startIndex,
          count,
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, { substring: output });
      }
    });
  });
});
