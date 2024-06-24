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

describe("Poseidon Hash Test", () => {
  let circuit: any;

  describe("Poseidon Hash Test", () => {
    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "./hash-sub-poseidon.circom"),
        {
          recompile: true,
          output: path.join(__dirname, "./compiled-test-circuit"),
          include: path.join(__dirname, "../node_modules"),
        }
      );
      loadSymbolsWorkaround(circuit);
    });

    it("should hash correctly", async function () {

      const data = {
        in: padString(
          "110117207114221115868",
          255
        )
      };

      const hash = '8302162597702278305042128676720696496998741886481537525071829641934989164098';

      const witness = await circuit.calculateWitness(data);
      console.log(witness);

      await circuit.assertOut(witness, {
        hash: hash
      });
    });
  });
});