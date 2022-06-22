import fs from "fs";
import { brotliCompressSync, unzip } from "zlib";
let compress = brotliCompressSync;

let WASM_FILE = "./circuit_js/circuit.wasm";
let ZKEY_FILE = "./circuit_final.zkey";

let wasm = fs.readFileSync(WASM_FILE);
let zkey = fs.readFileSync(ZKEY_FILE);

let json = {
  wasm: compress(wasm.buffer).toString("Base64"),
  zkey: compress(zkey.buffer).toString("Base64"),
};

console.log(JSON.stringify(json));
