// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

export const CIRCOM_BIGINT_N = 121;
export const CIRCOM_BIGINT_K = 17;

export function padString(str: string, paddedBytesSize: number): number[] {
  let paddedBytes = Array.from(str, (c) => c.charCodeAt(0));
  paddedBytes.push(...new Array(paddedBytesSize - paddedBytes.length).fill(0));
  return paddedBytes;
}

export function bigIntToChunkedBytes(
  // eslint-disable-next-line @typescript-eslint/ban-types
  num: BigInt | bigint,
  bytesPerChunk: number,
  numChunks: number
) {
  const res: string[] = [];
  const bigintNum: bigint = typeof num == "bigint" ? num : num.valueOf();
  const msk = (1n << BigInt(bytesPerChunk)) - 1n;
  for (let i = 0; i < numChunks; ++i) {
    res.push(((bigintNum >> BigInt(i * bytesPerChunk)) & msk).toString());
  }
  return res;
}

// eslint-disable-next-line @typescript-eslint/ban-types
export function toCircomBigIntBytes(num: BigInt | bigint) {
  return bigIntToChunkedBytes(num, CIRCOM_BIGINT_N, CIRCOM_BIGINT_K);
}
