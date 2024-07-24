import path from "path";
import { wasm as wasm_tester } from "circom_tester";
import { describe, beforeAll, it } from "vitest";
import { hexToBytes, padString, sha256PreimagePadding, bigIntToChunkedBytes } from "../utils";
import { loadSymbolsWorkaround } from "../utils/workarounds";


describe("Sha256 Id Hash Test", () => {
  let circuit: any;

  describe("Sha256 Id Hash Test", () => {
    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "../circuits/zkLoginSha256.circom"),
        {
          recompile: true,
          output: path.join(__dirname, "./compiled-test-circuit"),
          include: path.join(__dirname, "../node_modules"),
        }
      );
      loadSymbolsWorkaround(circuit);
    });

    it("should verify jwt and generate id hash", async function () {
      const publicKey = "xjWd1j8GmmWzuz732haG9HECXsSZBvxOBLph3FQhk_tplhWloI1ywx-RdopUZt1lndbOM9n99lZJkpQyNJ1sdy7JFgYLjqj-wtHdEaQlBGEQtmkW8zUjr_N3bmpsxGbPzOzlKe3qddtoxXvn9rI_RvHfJD1YY-6kayQeyPOBz_4ML1lvI_JHV-Bb1MSmSk3WaAh5PzeqleusmUT87Gqfu02cOPrY8cwugqo65D6-wzAEeVvceV8-c36TMoLU5csU05GBVplgd6Ouuw35ZsETG4si4QQJztC3KsZ4jhYM-aJ3jeFPt0r3cQooiXdZBp3JkXSpE-UUaOVPsXo7WiVmww==";
      const pubkeyBigInt = BigInt("0x" + Buffer.from(publicKey, "base64").toString("hex"));

      // signature
      const jwtSignature =
        "po6LchPr082VpjJjVliw6wItx32nBRh5a-w0T_6oQGz2N7MixGdvIeQ9gdOiyLOKPpz3NCR9oTf1V17Oxv1fgIgOP3wHThCEBToUbquAMKQjzUcujSsv3b2f0O3i28NwVBvtAYefdpvgxMEZot-S_US-2U9fBlI1ubkeLSOr4G_tLVPtR0iwfLLirW5NxR96oEp3BZ2BtSlDqLGlGXXFtNb4_Mvg40wzR4FT-RMb39zKlW0me7bcCZAwjuYEREptdYsUrHyDf72Q18NK2hBs6baNiBriNPwpHA5EyteH26SqaKYjaJGnEHPmSR4QrdwQX_LpvRlgETm_v6ZQw1t-Og";
      // eslint-disable-next-line prettier/prettier, no-restricted-globals
      const signatureBigInt = BigInt(
        "0x" + Buffer.from(jwtSignature, "base64").toString("hex")
      );

      const jwt = sha256PreimagePadding("eyJhbGciOiJSUzI1NiIsImtpZCI6IjMyM2IyMTRhZTY5NzVhMGYwMzRlYTc3MzU0ZGMwYzI1ZDAzNjQyZGMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3MzcwMjgwNDA4NTgtOHVmcXNvYzdpNWtmc3NkdGt1N3Rtc2dzc25tOGZjOGQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI3MzcwMjgwNDA4NTgtOHVmcXNvYzdpNWtmc3NkdGt1N3Rtc2dzc25tOGZjOGQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTAxMTcyMDcxMTQyMjExMTU4NjgiLCJhdF9oYXNoIjoic2hUS2RwcWpOU3RNc3IzTDE4Z285ZyIsIm5vbmNlIjoiNDI0MjQyNDI0MjQyNDI0MjQyNDI0MjQyNDI0MjQyNDI0MjQyNDI0MjQyNDI0MjQyNDI0MjQyNDI0MjQyNDI0MiIsImlhdCI6MTcxNjQ0OTgzNSwiZXhwIjoxNzE2NDUzNDM1fQ");

      let jwtBytes = Array.from(jwt);

      jwtBytes.push(...new Array(1088 - jwtBytes.length).fill(0));

      const data = {
        padded_unsigned_jwt: jwtBytes,
        payload_start_index: 103,
        payload_len: 498,
        num_sha2_blocks: 10,
        signature: bigIntToChunkedBytes(signatureBigInt, 64, 32),
        pubkey: bigIntToChunkedBytes(pubkeyBigInt, 64, 32),
        salt: Array.from(hexToBytes("a677999396dc49a28ad6c9c242719bb3"), (b) => b),
        sub_claim: padString(
          '"sub":"110117207114221115868",',
          264
        ), 
        sub_claim_length: 30,
        sub_index_b64: 103 + 265,
        sub_length_b64: 40,
        sub_name_length: 5,
        sub_colon_index: 5,
        sub_value_index: 6,
        sub_value_length: 23,
        nonce_claim: padString(
          '"nonce":"4242424242424242424242424242424242424242424242424242424242424242",',
          77
        ),
        nonce_claim_length: 75,
        nonce_index_b64: 103 + 352,
        nonce_length_b64: 101,
        nonce_name_length: 7,
        nonce_colon_index: 7,
        nonce_value_index: 8,
        nonce_value_length: 66,
      };

      const witness = await circuit.calculateWitness(data);

      const bytes = hexToBytes("2eab4af9ceb2865e42f4ead4d9decc71d4ecb1531f9b7521d1e309c2c2a02246");

      // Assert output with complete witness
      await circuit.assertOut(witness, {
        id_hash: [...bytes],
        nonce: padString('4242424242424242424242424242424242424242424242424242424242424242', 64),
      });
    });
  });
});