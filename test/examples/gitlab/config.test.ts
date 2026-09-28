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

import Ajv from 'ajv';
import fs from 'fs';
import path from 'path';
import { describe, expect, it } from 'vitest';

import { validate } from '../../../src/config/file';

const ROOT = path.resolve(__dirname, '../../..');
const CONFIG_PATH = path.join(ROOT, 'examples/gitlab/proxy.config.gitlab.json');
const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
const { $schema: _draft, ...schema } = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'config.schema.json'), 'utf-8'),
);

// Fake credentials are assembled at runtime so that secret scanners don't flag this file.
const fake = (...parts: string[]) => parts.join('');
const FAKE_SUFFIX = 'ExAmPlE0ExAmPlE0ExAm';

const matches = (pattern: string, text: string) => new RegExp(pattern, 'gi').test(text);

describe('examples/gitlab/proxy.config.gitlab.json', () => {
  it('is valid against config.schema.json (ajv)', () => {
    const ajv = new Ajv({ allErrors: true, strict: false, validateFormats: false });
    const valid = ajv.validate(schema, config);
    expect(ajv.errors ?? []).toEqual([]);
    expect(valid).toBe(true);
  });

  it('is accepted by the GitProxy config validator', () => {
    expect(validate(CONFIG_PATH)).toBe(true);
  });

  it('references plugin files that exist', () => {
    expect(config.plugins).toHaveLength(3);
    for (const plugin of config.plugins) {
      expect(fs.existsSync(path.join(ROOT, plugin)), plugin).toBe(true);
    }
  });

  it('authorises a nested gitlab.com group and a self-hosted GitLab repository', () => {
    const urls = config.authorisedList.map((repo: { url: string }) => new URL(repo.url));
    expect(urls.every((url: URL) => url.protocol === 'https:')).toBe(true);
    expect(
      urls.some((url: URL) => url.host === 'gitlab.com' && url.pathname.split('/').length > 3),
    ).toBe(true);
    expect(urls.some((url: URL) => url.host === 'gitlab.example.internal')).toBe(true);
  });

  it('only allows corporate author email domains and blocks service-account locals', () => {
    const { domain, local } = config.commitConfig.author.email;
    expect(matches(domain.allow, 'acme.example')).toBe(true);
    expect(matches(domain.allow, 'eng.acme.example')).toBe(true);
    expect(matches(domain.allow, 'users.noreply.gitlab.com')).toBe(false);
    expect(matches(domain.allow, 'acme.example.evil.com')).toBe(false);
    for (const blocked of ['noreply', 'no-reply', 'root', 'admin', 'jdoe+spam']) {
      expect(matches(local.block, blocked), blocked).toBe(true);
    }
    expect(matches(local.block, 'jane.doe')).toBe(false);
    expect(matches(local.block, 'rooty')).toBe(false);
  });

  it('blocks WIP / do-not-merge / fixup commit messages', () => {
    const { literals, patterns } = config.commitConfig.message.block;
    const isBlocked = (message: string) =>
      literals.some((literal: string) => message.toLowerCase().includes(literal.toLowerCase())) ||
      patterns.some((pattern: string) => matches(pattern, message));

    for (const message of [
      'WIP: PAY-1 half done',
      'Draft PAY-1',
      'fixup! PAY-1: add endpoint',
      'squash! PAY-1',
      'PAY-1: do not merge yet',
      'PAY-1 DO-NOT-MERGE',
      'PAY-1: skip pipeline [skip ci]',
    ]) {
      expect(isBlocked(message), message).toBe(true);
    }
    for (const message of ['PAY-1: wipe cache on logout', 'PAY-2: add draft invoices']) {
      expect(isBlocked(message), message).toBe(false);
    }
  });

  it('detects GitLab, AWS and private key secrets in diffs', () => {
    const { patterns, providers } = config.commitConfig.diff.block;
    const rules: string[] = [...patterns, ...Object.values<string>(providers)];
    const detected = (text: string) => rules.some((rule) => matches(rule, text));

    for (const secret of [
      fake('gl', 'pat-', FAKE_SUFFIX),
      fake('gl', 'rt-', FAKE_SUFFIX),
      fake('gl', 'dt-', FAKE_SUFFIX),
      fake('gl', 'ptt-', 'a'.repeat(40)),
      fake('AK', 'IA', 'Z'.repeat(16)),
      fake('-----BEGIN ', 'OPENSSH PRIVATE', ' KEY-----'),
      fake('-----BEGIN ', 'PRIVATE', ' KEY-----'),
    ]) {
      expect(detected(`+const token = "${secret}";`), secret.slice(0, 8)).toBe(true);
    }
    expect(detected('+const token = process.env.GITLAB_TOKEN;')).toBe(false);
    expect(detected(fake('gl', 'pat-', 'short'))).toBe(false);
  });

  it('enables gitleaks and tailored attestation questions', () => {
    expect(config.api.gitleaks.enabled).toBe(true);
    expect(config.attestationConfig.questions.length).toBeGreaterThanOrEqual(3);
    expect(config.privateOrganizations.length).toBeGreaterThan(0);
  });
});
