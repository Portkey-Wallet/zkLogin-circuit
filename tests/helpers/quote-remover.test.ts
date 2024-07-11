// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

import fs from "fs";
import path from "path";
import { pki } from "node-forge";
import { wasm as wasm_tester } from "circom_tester";
import { padString, toCircomBigIntBytes } from "../../utils";
import { describe, beforeAll, it } from "vitest";

describe("Quote Remover Test", () => {
  let circuit: any;

  describe("Quote remover", () => {
    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "./circuits/quote-remover-test.circom"),
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

    
    it("should remove quotes", async function () {
      const data = {
        in: padString(
          '"sub"',
          20
        ),
        length: 5,
      }
      
      const witness = await circuit.calculateWitness(data);

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        out: padString('sub', 18),
      });
    });
  });
});
