/**
 * Copyright 2026 GitProxy Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { describe, it, expect, vi } from 'vitest';
import { deflateSync } from 'zlib';

vi.mock('../src/proxy/processors/constants', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/proxy/processors/constants')>()),
  MAX_INFLATED_OBJECT_SIZE: 1024,
  MAX_INFLATED_PACK_SIZE: 4096,
}));

import { getContents } from '../src/proxy/processors/push-action/parsePush';

const BLOB_TYPE = 3;

const encodeHeader = (type: number, size: number): Buffer => {
  const bytes: number[] = [];
  let byte = (type << 4) | (size & 0x0f);
  size >>= 4;
  while (size > 0) {
    bytes.push(byte | 0x80);
    byte = size & 0x7f;
    size >>= 7;
  }
  bytes.push(byte);
  return Buffer.from(bytes);
};

const buildContents = (sizes: number[]): Buffer =>
  Buffer.concat([
    ...sizes.map((size) =>
      Buffer.concat([encodeHeader(BLOB_TYPE, size), deflateSync(Buffer.alloc(size, 'a'))]),
    ),
    Buffer.alloc(32),
  ]);

describe('parsePush inflation limits', () => {
  it('accepts objects within the per-object and per-pack limits', async () => {
    const contents = await getContents(buildContents([1024, 1000, 1000, 1000]), 4);

    expect(contents.map((c) => c.content.length)).toEqual([1024, 1000, 1000, 1000]);
  });

  it('rejects an object whose inflated size exceeds MAX_INFLATED_OBJECT_SIZE', async () => {
    await expect(getContents(buildContents([1025]), 1)).rejects.toThrowError(
      /object at offset 0 exceeds the maximum inflated object size of 1024 bytes/,
    );
  });

  it('rejects a pack whose combined inflated size exceeds MAX_INFLATED_PACK_SIZE', async () => {
    await expect(
      getContents(buildContents([1000, 1000, 1000, 1000, 1000]), 5),
    ).rejects.toThrowError(/PACK exceeds the maximum inflated size of 4096 bytes/);
  });

  it('rejects a pack once the budget is exhausted exactly', async () => {
    await expect(getContents(buildContents([1024, 1024, 1024, 1024, 10]), 5)).rejects.toThrowError(
      /PACK exceeds the maximum inflated size of 4096 bytes/,
    );
  });
});
