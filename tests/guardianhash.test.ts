import fs from "fs";
import path from "path";
import { pki } from "node-forge";
import { wasm as wasm_tester } from "circom_tester";
import { describe, beforeAll, it } from "vitest";
import { hexToBytes, padString, toCircomBigIntBytes } from "../utils";

// Function to split large files into smaller chunks
const splitFile = (filePaths: string[], chunkSize: number): Buffer[] => {
  const chunks: Buffer[] = [];

  for (const filePath of filePaths) {
    const fileBuffer = fs.readFileSync(filePath);
    chunks.push(...splitBuffer(fileBuffer, chunkSize));
  }

  return chunks;
};

/// Function to split large buffers into smaller chunks
const splitBuffer = (buffer: Buffer, chunkSize: number): Buffer[] => {
  const chunks: Buffer[] = [];
  for (let i = 0; i < buffer.length; i += chunkSize) {
    chunks.push(buffer.slice(i, i + chunkSize));
  }
  return chunks;
};

describe("Guardian Hash Test", () => {
  let circuit: any;

  describe("Guardian Hash Test", () => {
    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "../circuits/guardianhash.circom"),
        {
          recompile: true,
          output: path.join(__dirname, "./compiled-test-circuit"),
          include: path.join(__dirname, "../node_modules"),
        }
      );
    });

    it("should main be ok", async function () {

      const publicKey = "uhWRpJ3PNZaiBmq3P91A6QB0b28LeQvV-HI0TAEcN5nffQPm94w-hY2S6mThb7xXLCGHcP3bhpWl31giZJFlvzHe6db-TsPl8HSLgLIjMbMT8iYWqZPa2eodijEJrkO6SPex5jHLzSwGsoRdSfW8hFeTFQk8xtPXm7GlEEo9mFEKUAaArT9acdE8h53VR7ZkJkipiLCtx0rhySA2W4rEAcinLG3ApG709pOw6sVjA2IAQmZVYrfQ7curmFqKWL_F534kDhQJL2hMdrubhHcqCxetyi_U7WDWDkYCJ_CetjDsI0yfwB2sR01vn6LuDDo6ho8pWJcHOOvXYUnSMFAlew";

      // signature
      const jwtSignature =
        "JFKnx1lHSiOYq9f_cs-favTCPDAk8WBiQafm_-Gwbm5zneiOkT01act3RWe3iH3UcjhpteW3q0c1CS_YmFEk17zVFNqABIzgljZ2YRB1C1VaPzfzxSF3aSIj-WzOtpk08SJS5QkRspoqkrE3XoT5Fm2sISu__CIcf2CFCSR77LLObEi09OfZkuWFPTK20HnY7t7PheymlBznUK7etxLoR0mUQ3nbvs8ONPYoCCYMvtqqM8l5lq06nUa6zBmANCxBKeRx--Ia-rMjLGVMax1yn4qAx_bGAi4GO0bAkftD71eWt7YdeADsP0ttuj1wDLS14xXtSjbhJCuUyImce0vYpQ";
      // eslint-disable-next-line prettier/prettier, no-restricted-globals
      const signatureBigInt = BigInt(
        "0x" + Buffer.from(jwtSignature, "base64").toString("hex")
      );


      const pubkeyBigInt = BigInt("0x" + Buffer.from(publicKey, "base64").toString("hex"));

      const data = {
        jwt: padString(
          "eyJhbGciOiJSUzI1NiIsImtpZCI6IjkzNGE1ODE2NDY4Yjk1NzAzOTUzZDE0ZTlmMTVkZjVkMDlhNDAxZTQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3MzcwMjgwNDA4NTgtOHVmcXNvYzdpNWtmc3NkdGt1N3Rtc2dzc25tOGZjOGQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI3MzcwMjgwNDA4NTgtOHVmcXNvYzdpNWtmc3NkdGt1N3Rtc2dzc25tOGZjOGQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTAxMTcyMDcxMTQyMjExMTU4NjgiLCJlbWFpbCI6InN0ZXZlbmRlbmc4NkBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IjBYRFlzLURESzNKdmR4blY5bnJxcEEiLCJuYW1lIjoiR3VhbmdsZWkgRGVuZyIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NLVGZ6OFpPLS1TZGFjdzVMVFhlbVQxNllwTlNsQm9ncFIzSHEzdWJIQ0w9czk2LWMiLCJnaXZlbl9uYW1lIjoiR3VhbmdsZWkiLCJmYW1pbHlfbmFtZSI6IkRlbmciLCJpYXQiOjE3MTIxNDIyMzcsImV4cCI6MTcxMjE0NTgzN30",
          2048
        ),
        signature: toCircomBigIntBytes(signatureBigInt),
        pubkey: toCircomBigIntBytes(pubkeyBigInt),
        salt: Array.from(hexToBytes("a677999396dc49a28ad6c9c242719bb3"), (b) => b),
        payload_start_index: 103,
        sub_claim: padString(
          '"sub":"110117207114221115868",',
          41
        ), 
        sub_claim_length: 30,
        sub_index_b64: 103 + 265,
        sub_length_b64: 42,
        sub_name_length: 5,
        sub_colon_index: 5,
        sub_value_index: 6,
        sub_value_length: 23,
      };

      const witness = await circuit.calculateWitness(data);

      const bytes = hexToBytes("2eab4af9ceb2865e42f4ead4d9decc71d4ecb1531f9b7521d1e309c2c2a02246");

      // Assert output with complete witness
      await circuit.assertOut(witness, {
        out: [...bytes],
      });
    });
  });
});