import fs from "fs";
import path from "path";
import { pki } from "node-forge";
import { wasm as wasm_tester } from "circom_tester";
import { describe, beforeAll, it } from "vitest";
import { hexToBytes, padString, toCircomBigIntBytes, bigIntToChunkedBytes, sha256PreimagePadding } from "../utils";
import { loadSymbolsWorkaround } from "../utils/workarounds";

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

describe("zkLogin Test", () => {
  let circuit: any;

  describe("zkLogin Test", () => {
    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "../circuits/zkLogin.circom"),
        {
          recompile: true,
          output: path.join(__dirname, "./compiled-test-circuit"),
          include: path.join(__dirname, "../node_modules"),
        }
      );
      loadSymbolsWorkaround(circuit);
    });


    it("should verify jwt and generate id hash", async function () {
      const publicKey = "rhgQZT3t9MgNBv9_4qE58CLCbDfEaRd9HgPd_Zmjg1TIYjHh1UgMPVeVekyU2JiuUZPbnlEbv8WUsxyNNQJfATvfMbXaUcrePSdW32zIaMOeTbn0VXZ3tqx5IyiP0IfJt-kT9MilGAkeJn8me7x5_uNGOpiPCWQaxFxTikVUtGO5AbGh2PTULzKjVjZWwQrPB1fqEe6Ar6Im-3RcZ-zOd3N2ThgQEzLLRe4RE6bSvBQUuxX9o_AkY0SCVZZB2VhjQYBN3EUFmKsD46rrneBn64Vduy3jWtBYXA1avDRCl0Y8yQEBOrtgikEz_hog4O4EKP5mAVSf8Iyfl_RMdxrOAQ";
      const pubkeyBigInt = BigInt("0x" + Buffer.from(publicKey, "base64").toString("hex"));

      // signature
      const jwtSignature =
        "hnI69slCu-aHQKftEX4jIR1ZVtfjcLYzi0vp11Lly1O9t6RbZT9f_og3ZJ_UzseiW9Opam5Ke4iaq_ZnHES8bvTdVYhpfqbb39xGWIJXDjEeNe1FyeF7RkukeFUUFdfikGoKO0UObD5gNm7v6KnnjmHxRpmIFbRZLJXuqoFQjwxfD_1yKmHkg9UjC1JplaTtb6nrl4ocw2KOBprWDWG7jiFJhkZqEmXslR8S7Atyg0fbDyt2pTHbLV-yaIvb6V4JTCZlgJPKze5g-z1YLv1FNiLSWfaRclU0DUOxLnwqcgWVwsXCsuauEXyzi689MfRvnAJkdd5HLe9jdWYQyzQSZA";
      // eslint-disable-next-line prettier/prettier, no-restricted-globals
      const signatureBigInt = BigInt(
        "0x" + Buffer.from(jwtSignature, "base64").toString("hex")
      );

      const jwt = sha256PreimagePadding("eyJhbGciOiJSUzI1NiIsImtpZCI6IjNkNTgwZjBhZjdhY2U2OThhMGNlZTdmMjMwYmNhNTk0ZGM2ZGJiNTUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiMTc2MTQ3NzQ0NzMzLWEya3M2ODF1dXFybWI4YWpxcnB1MTd0ZTQyZ3N0NmxxLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTc2MTQ3NzQ0NzMzLWEya3M2ODF1dXFybWI4YWpxcnB1MTd0ZTQyZ3N0NmxxLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTE2MDQ5MzgxNjMxMjI0Nzc0OTA3IiwiZW1haWwiOiJpbmZvLnBvcnRrZXkuZmluYW5jZUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IjFUWnZxNnVXbC1OZVdzV0x2bHNDb1EiLCJub25jZSI6ImE2Nzc5OTkzOTZkYzQ5YTI4YWQ2YzljMjQyNzE5YmIzYTY3Nzk5OTM5NmRjNDlhMjhhZDZjOWMyNDI3MTliYjMiLCJuYmYiOjE3MTkzMDEzNjYsImlhdCI6MTcxOTMwMTY2NiwiZXhwIjoxNzE5MzA1MjY2LCJqdGkiOiI2MTdjY2VmODgzMTQ1OTA0YjI3ZDYxZjEwNjIwODAwNzU3NGRjMWVkIn0");

      let jwtBytes = Array.from(jwt);

      jwtBytes.push(...new Array(1088 - jwtBytes.length).fill(0));

      const data = {
        padded_unsigned_jwt: jwtBytes,
        payload_start_index: 103,
        payload_len: 659,
        num_sha2_blocks: 13,
        signature: bigIntToChunkedBytes(signatureBigInt, 64, 32),
        pubkey: bigIntToChunkedBytes(pubkeyBigInt, 64, 32),
        salt: Array.from(hexToBytes("a677999396dc49a28ad6c9c242719bb3"), (b) => b),
        sub_claim: padString(
          '"sub":"116049381631224774907",',
          264
        ), 
        sub_claim_length: 30,
        sub_index_b64: 357,
        sub_length_b64: 42,
        sub_name_length: 5,
        sub_colon_index: 5,
        sub_value_index: 6,
        sub_value_length: 23,
        nonce_claim: padString(
          '"nonce":"a677999396dc49a28ad6c9c242719bb3a677999396dc49a28ad6c9c242719bb3",',
          77
        ),
        nonce_claim_length: 75,
        nonce_index_b64: 528,
        nonce_length_b64: 101,
        nonce_name_length: 7,
        nonce_colon_index: 7,
        nonce_value_index: 8,
        nonce_value_length: 66,
      };

      const witness = await circuit.calculateWitness(data);

      // Assert output with complete witness
      await circuit.assertOut(witness, {
        id_hash: '8208523664675913588953211964152238115542069990215959182578005311778533289585',
        nonce: padString('a677999396dc49a28ad6c9c242719bb3a677999396dc49a28ad6c9c242719bb3', 64),
      });
    });

  });
});