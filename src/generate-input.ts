import fs from "fs";
import path from "path";
import { pki } from "node-forge";
import { padString, toCircomBigIntBytes } from "../utils";

export const generateInput = ({
  jwtSignature = "NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
  jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
  sub = "116111375152810828167",
  salt = "a677999396dc49a28ad6c9c242719bb3",
}) => {
  // eslint-disable-next-line prettier/prettier, no-restricted-globals
  const signatureBigInt = BigInt(
    "0x" + Buffer.from(jwtSignature, "base64").toString("hex")
  );

  // public key
  // TODO: generate using jose from remote jwk https://github.com/panva/jose
  const publicKeyPem = fs.readFileSync(
    path.join(__dirname, "../tests/keys/public_key.pem"),
    "utf8"
  );
  const pubKeyData = pki.publicKeyFromPem(publicKeyPem.toString());
  const pubkeyBigInt = BigInt(pubKeyData.n.toString());

  const input = {
    jwt: padString(jwt, 512),
    signature: toCircomBigIntBytes(signatureBigInt),
    pubkey: toCircomBigIntBytes(pubkeyBigInt),
    sub: padString(sub, 512),
    salt: padString(salt, 512),
  };

  return input;
};
