export function padBytes(
  arr: Uint8Array | number[],
  paddedBytesSize: number
): number[] {
  let paddedBytes = Array.from(arr, (c) => c);
  paddedBytes.push(...new Array(paddedBytesSize - paddedBytes.length).fill(0));
  return paddedBytes;
}
