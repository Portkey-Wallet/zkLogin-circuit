import path from "path";
import { wasm } from "circom_tester";
import { describe, it } from "vitest";

describe("Simple test", function () {
  it("Checking the compilation of a simple circuit generating wasm", async function () {
    const circuit = await wasm(
      path.join(__dirname, "..", "circuits", "sha256.circom")
    );

    const w = await circuit.calculateWitness({
      sub: [
        "1",
        "1",
        "6",
        "1",
        "1",
        "1",
        "3",
        "7",
        "5",
        "1",
        "5",
        "2",
        "8",
        "1",
        "0",
        "8",
        "2",
        "8",
        "1",
        "6",
        "7",
      ],
    });
    await circuit.checkConstraints(w);
  });
});
