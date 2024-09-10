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

describe("Id Hash Mapping Test", () => {
  let circuit: any;

  describe("Id Hash Mapping Test", () => {
    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "../circuits/idHashMapping.circom"),
        {
          recompile: true,
          output: path.join(__dirname, "./compiled-test-circuit"),
          include: path.join(__dirname, "../node_modules"),
        }
      );
      loadSymbolsWorkaround(circuit);
    });

    it("should map sha256 based and poseidon based id (two times hash with salt) correctly", async function () {

      const data = {
        sub: padString(
          "110117207114221115868",
          255
        ),
        subLen: 21,
        salt: Array.from(hexToBytes("a677999396dc49a28ad6c9c242719bb3"), (b) => b),
      };
      // will be packed into [13846356912322354, 85189581377597132177622858375434543549286969422497087616931493135530328064, 0,0,0,0,0,0,0]

      const hash = '9340168379609132233074617967082586477056958824754337733208830122770402483169';
      // 0x14a659140561cd5f31fea523b96f5f6284896f23987bdefe453d4367a42d9be1

      const bytes = hexToBytes("2eab4af9ceb2865e42f4ead4d9decc71d4ecb1531f9b7521d1e309c2c2a02246");

      const witness = await circuit.calculateWitness(data);

      await circuit.assertOut(witness, {
        sha256_hash: [...bytes],
        poseidon_hash: hash
      });
    });
  });
});