export function sha256PreimagePadding(message) {
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
