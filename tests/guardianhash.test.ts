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
      // Signature
      const jwtSignature =
        "NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";
      const signatureBigInt = BigInt("0x" + Buffer.from(jwtSignature, "base64").toString("hex"));

      // Public key
      const publicKeyPem = fs.readFileSync(
        path.join(__dirname, "./keys/public_key.pem"),
        "utf8"
      );
      const pubKeyData = pki.publicKeyFromPem(publicKeyPem.toString());
      const pubkeyBigInt = BigInt(pubKeyData.n.toString());

      // Read large files and split into smaller chunks
      const filePaths = [/* Add file paths here */];
      const chunkSize = 1024 * 1024; // 1 MB
      const chunks: Buffer[] = [];
      for (const filePath of filePaths) {
        const fileBuffer = fs.readFileSync(filePath);
        chunks.push(...splitBuffer(fileBuffer, chunkSize));
      }

      // Initialize startTime
      const startTime = new Date().getTime();
      
      // Calculate witness for each chunk
      for (const chunk of chunks) {
        const witness = await circuit.calculateWitness({
          jwt: padString(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
            2048
          ),
          signature: toCircomBigIntBytes(signatureBigInt),
          pubkey: toCircomBigIntBytes(pubkeyBigInt),
          salt: Array.from(hexToBytes("a677999396dc49a28ad6c9c242719bb3"), (b) => b),
        });

        // Check constraints for each witness chunk
        await circuit.checkConstraints(witness);
      }

      // Sub is "1234567890"
      const bytes = hexToBytes("7f0bdbbd5bc4c68c21afe63067d39bbc863432cec2c56b9d351cad89346a8b47");

      // Assert output with complete witness
      await circuit.assertOut(chunks.join(), {
        out: [...bytes],
      });
    });
  });
});