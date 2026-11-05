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

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import { Request } from 'express';
import { exec as pullRemote } from '../../src/proxy/processors/push-action/pullRemote';
import { Action } from '../../src/proxy/actions/Action';

const remoteFolder = './.remote';
const createdRemoteFolder = !fs.existsSync(remoteFolder);

describe('pullRemote checkout folder', () => {
  beforeAll(() => {
    fs.mkdirSync(`${remoteFolder}/a__b`, { recursive: true });
  });

  afterAll(() => {
    fs.rmSync(`${remoteFolder}/a__b`, { recursive: true, force: true });
    if (createdRemoteFolder) {
      fs.rmSync(remoteFolder, { recursive: true, force: true });
    }
  });

  it.each(['a__b/../escaped', '../escaped', 'a__b/nested', '..', '.', '/etc', ''])(
    'rejects action id %j that does not map to a single folder inside .remote',
    async (id) => {
      const action = new Action(id, 'push', 'POST', Date.now(), 'finos/git-proxy.git');

      await expect(pullRemote({ headers: {} } as Request, action)).rejects.toThrow(
        'Invalid checkout folder for this push.',
      );

      expect(action.proxyGitPath).toBeUndefined();
      expect(action.steps[0].error).toBe(true);
      expect(fs.existsSync(`${remoteFolder}/escaped`)).toBe(false);
      expect(fs.existsSync('./escaped')).toBe(false);
      expect(fs.existsSync(`${remoteFolder}/a__b/nested`)).toBe(false);
    },
  );
});
