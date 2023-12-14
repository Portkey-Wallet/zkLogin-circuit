// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

import { wasm as wasm_tester } from "circom_tester";
import path from "path";
import { padString } from "../utils";
import { describe, beforeAll, it } from "vitest";

describe("IndexOf Test", () => {
  let circuit: any;

  describe("IndexOf test", () => {
    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "./string-indexof-test.circom"),
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

    it("should IndexOf be ok", async function () {
      const inputs = [
        [padString("A", 256), "A".charCodeAt(0), 0], // A
        [padString("AB", 256), "B".charCodeAt(0), 1], // B
      ];

      for (const [text, targetChar, output] of inputs) {
        const witness = await circuit.calculateWitness({
          text,
          startIndex: 0,
          targetChar,
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, { index: output });
      }
    });

    it("should return the correct index for the last position of the sub", async function () {
      const inputs = [
        [
          padString(
            '{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}',
            256
          ),
          '"'.charCodeAt(0),
          8,
          18,
        ],
      ];

      for (const [text, targetChar, startIndex, output] of inputs) {
        const witness = await circuit.calculateWitness({
          text,
          startIndex,
          targetChar,
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, { index: output });
      }
    });
  });
});
