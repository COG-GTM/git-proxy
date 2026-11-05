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

import { describe, it, expect, vi, afterEach } from 'vitest';
import { Step } from '../src/proxy/actions';

describe('Step.log', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('keeps short messages unchanged in both the step logs and the console', () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
    const step = new Step('test');

    step.log('Scanning diff: abc:def');

    expect(step.logs).toEqual(['test - Scanning diff: abc:def']);
    expect(infoSpy).toHaveBeenCalledWith('test - Scanning diff: abc:def');
  });

  it('writes only the first line of multi-line messages to the console', () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
    const step = new Step('test');
    const message = '\n\nYour push has been blocked.\nDETECTED: AKIAIOSFODNN7EXAMPLE';

    step.log(message);

    expect(step.logs).toEqual([`test - ${message}`]);
    expect(infoSpy).toHaveBeenCalledTimes(1);
    const output = infoSpy.mock.calls[0][0] as string;
    expect(output).toMatch(/^test - Your push has been blocked\. \[truncated, \d+ chars\]$/);
    expect(output).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('truncates long single-line messages on the console', () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
    const step = new Step('test');
    const message = 'a'.repeat(500);

    step.log(message);

    expect(step.logs).toEqual([`test - ${message}`]);
    const output = infoSpy.mock.calls[0][0] as string;
    expect(output).toBe(`test - ${'a'.repeat(200)} [truncated, 500 chars]`);
  });

  it('keeps messages logged with console: false out of the console', () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
    const step = new Step('test');

    step.log('illegal: AKIAIOSFODNN7EXAMPLE', { console: false });

    expect(step.logs).toEqual(['test - illegal: AKIAIOSFODNN7EXAMPLE']);
    expect(infoSpy).not.toHaveBeenCalled();
  });

  it('does not echo setError messages beyond their first line to the console', () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
    const step = new Step('scanDiff');

    step.setError('\n\nYour push has been blocked.\n\nDETECTED: blocked.Te$t.Literal?');

    expect(step.errorMessage).toContain('blocked.Te$t.Literal?');
    const output = infoSpy.mock.calls.map((args) => args.join(' ')).join('\n');
    expect(output).not.toContain('blocked.Te$t.Literal?');
  });
});
