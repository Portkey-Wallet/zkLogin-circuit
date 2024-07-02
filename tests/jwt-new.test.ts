import fs from "fs";
import path from "path";
import { pki } from "node-forge";
import { wasm as wasm_tester } from "circom_tester";
import { describe, beforeAll, it } from "vitest";
import { loadSymbolsWorkaround } from "../utils/workarounds";
import { bigIntToChunkedBytes } from "../utils/big-int-to-chunked-bytes";

function sha256PreimagePadding(message) {
  // Convert the message to bytes
  const messageBytes = new TextEncoder().encode(message);

  // Step 1: Append '1' bit
  let paddedBytes = new Uint8Array([...messageBytes, 0x80]);
  const bitsMod512 = (paddedBytes.length * 8) % 512;

  // Step 2: Add zero bits
  let k = 448 - bitsMod512;
  if (k < 0) k += 512;
  paddedBytes = new Uint8Array([...paddedBytes, ...new Array(k / 8).fill(0)]);

  // Step 3: Append original message length (64 bits)
  const originalLengthBits = BigInt(messageBytes.length * 8);
  const lengthBytes = new BigUint64Array([originalLengthBits]);
  paddedBytes = new Uint8Array([...paddedBytes, ...new Uint8Array(lengthBytes.buffer).reverse()]);

  return paddedBytes;
}

describe("jwt verify test", () => {
  let circuit: any;

  describe("jwt verify test", () => {
    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "./jwt-new.circom"),
        {
          recompile: true,
          output: path.join(__dirname, "./compiled-test-circuit"),
          include: path.join(__dirname, "../node_modules"),
        }
      );
      loadSymbolsWorkaround(circuit);
    });

    it("should verify apple jwt", async function () {


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

      jwtBytes.push(...new Array(1024 - jwtBytes.length).fill(0));

      const data = {
        padded_unsigned_jwt: jwtBytes,
        payload_start_index: 103,
        payload_len: 659,
        num_sha2_blocks: 13,
        signature: bigIntToChunkedBytes(signatureBigInt, 64, 32),
        modulus: bigIntToChunkedBytes(pubkeyBigInt, 64, 32),
      };
      await circuit.calculateWitness(data);
    });
  });
});