// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

import fs from "fs";
import path from "path";
import { pki } from "node-forge";
import { wasm as wasm_tester } from "circom_tester";
import { padString, toCircomBigIntBytes } from "../utils";
import { describe, beforeAll, it } from "vitest";

describe("JWT Checks Test", () => {
  let circuit: any;

  describe("JWT Checks", () => {
    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "./jwtchecks-test.circom"),
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

    
    it("should JWT Checks be ok", async function () {
      const data = {
        content: padString(
          "eyJhbGciOiJSUzI1NiIsImtpZCI6IjkzNGE1ODE2NDY4Yjk1NzAzOTUzZDE0ZTlmMTVkZjVkMDlhNDAxZTQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3MzcwMjgwNDA4NTgtOHVmcXNvYzdpNWtmc3NkdGt1N3Rtc2dzc25tOGZjOGQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI3MzcwMjgwNDA4NTgtOHVmcXNvYzdpNWtmc3NkdGt1N3Rtc2dzc25tOGZjOGQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTAxMTcyMDcxMTQyMjExMTU4NjgiLCJlbWFpbCI6InN0ZXZlbmRlbmc4NkBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IjBYRFlzLURESzNKdmR4blY5bnJxcEEiLCJuYW1lIjoiR3VhbmdsZWkgRGVuZyIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NLVGZ6OFpPLS1TZGFjdzVMVFhlbVQxNllwTlNsQm9ncFIzSHEzdWJIQ0w9czk2LWMiLCJnaXZlbl9uYW1lIjoiR3VhbmdsZWkiLCJmYW1pbHlfbmFtZSI6IkRlbmciLCJpYXQiOjE3MTIxNDIyMzcsImV4cCI6MTcxMjE0NTgzN30",
          2048
        ),
        index_b64: 103 + 264,
        // index_b64: 198,
        length_b64: 42,
        payload_start_index: 103,

        ext_claim: padString(
          ',"sub":"110117207114221115868",',
          256
        ), // correct
        ext_claim_length: 31,
        name_length: 6,
        colon_index: 6,
        value_index: 7,
        value_length: 23,
      }
      
      const witness = await circuit.calculateWitness(data);

      await circuit.checkConstraints(witness);
      const claim_name = ',"sub"';
      const claim_value = '"110117207114221115868"';
      await circuit.assertOut(witness, {
        claim_name: padString(claim_name, claim_name.length),
        claim_value: padString(claim_value, claim_value.length)
      });
    });
  });
});
