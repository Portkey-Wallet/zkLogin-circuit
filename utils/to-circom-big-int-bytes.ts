// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

import { CIRCOM_BIGINT_N, CIRCOM_BIGINT_K } from "../constants";
import { bigIntToChunkedBytes } from "./big-int-to-chunked-bytes";

// eslint-disable-next-line @typescript-eslint/ban-types
export function toCircomBigIntBytes(num: BigInt | bigint) {
  return bigIntToChunkedBytes(num, CIRCOM_BIGINT_N, CIRCOM_BIGINT_K);
}
