// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

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
