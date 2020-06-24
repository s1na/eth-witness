import { Nibbles } from '../trieNode'

/**
 * Converts a buffer to a nibble array.
 * @private
 * @param {Buffer} key
 */
export function bufferToNibbles(key: Buffer): Nibbles {
  const bkey = Buffer.from(key)
  let nibbles = [] as any

  for (let i = 0; i < bkey.length; i++) {
    let q = i * 2
    nibbles[q] = bkey[i] >> 4
    ++q
    nibbles[q] = bkey[i] % 16
  }

  return nibbles
}

/**
 * Converts a nibble array into a buffer.
 * @private
 * @param {Nibbles} arr - Nibble array
 */
export function nibblesToBuffer(arr: Nibbles): Buffer {
  let buf = Buffer.alloc(arr.length / 2)
  for (let i = 0; i < buf.length; i++) {
    let q = i * 2
    buf[i] = (arr[q] << 4) + arr[++q]
  }
  return buf
}

/**
 * Returns the number of in order matching nibbles of two give nibble arrays.
 * @private
 * @param {Nibbles} nib1
 * @param {Nibbles} nib2
 */
export function matchingNibbleLength(nib1: Nibbles, nib2: Nibbles): number {
  let i = 0
  while (nib1[i] === nib2[i] && nib1.length > i) {
    i++
  }
  return i
}

/**
 * Compare two nibble array keys.
 * @param {Nibbles} keyA
 * @param {Nibbles} keyB
 */
export function doKeysMatch(keyA: Nibbles, keyB: Nibbles): boolean {
  const length = matchingNibbleLength(keyA, keyB)
  return length === keyA.length && length === keyB.length
}