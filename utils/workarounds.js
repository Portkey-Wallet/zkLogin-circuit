
const fs = require("fs");
const path = require("path");
const readline = require("readline");

async function readNLines(filePath, linesToRead) {
    const readStream = fs.createReadStream(filePath, { encoding: 'utf-8' });
    const rl = readline.createInterface({
        input: readStream,
        crlfDelay: Infinity,
    });
  
    let linesRead = 0;
    let lines = "";
    for await (const line of rl) {
        lines += line + "\n";
  
        linesRead++;
  
        // If the desired number of lines has been reached, close the interface
        if (linesRead === linesToRead) {
            rl.close();
            return lines;
        }
    }
    rl.close();
    return lines;
  }
  

function loadSymbolsWorkaround(wasmTester) {
    wasmTester.loadSymbols = 
    async function() {
        if (this.symbols) return;
        this.symbols = {};
        const filePath = path.join(this.dir, this.baseName + ".sym");
        const symsStr = await readNLines(filePath, 610);
        const lines = symsStr.split("\n");
        for (let i = 0; i < lines.length; i++) {
            const arr = lines[i].split(",");
            if (arr.length != 4) continue;
            this.symbols[arr[3]] = {
                labelIdx: Number(arr[0]),
                varIdx: Number(arr[1]),
                componentIdx: Number(arr[2]),
            };
        }
    };
    return wasmTester;
}

module.exports = {
    loadSymbolsWorkaround,
};
