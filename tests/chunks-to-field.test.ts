import fs from "fs";
import path from "path";
import { pki } from "node-forge";
import { wasm as wasm_tester } from "circom_tester";
import { describe, beforeAll, it } from "vitest";
import { hexToBytes, padString, toCircomBigIntBytes } from "../utils";
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

describe("Convert Bytes to Field Test", () => {
  let circuit: any;

  describe("Convert Bytes to Field Test", () => {
    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "./chunks-to-field.circom"),
        {
          recompile: true,
          output: path.join(__dirname, "./compiled-test-circuit"),
          include: path.join(__dirname, "../node_modules"),
        }
      );
      loadSymbolsWorkaround(circuit);
    });

    it("should convert", async function () {

      const data = {
        in: Array.from(hexToBytes("a677999396dc49a28ad6c9c242719bb3"), (b) => b)
      };

      const witness = await circuit.calculateWitness(data);
      console.log(witness);

      // Assert output with complete witness
      await circuit.assertOut(witness, {
        out: '238738914460200877251263498453947873190'
      });
    });
  });
});