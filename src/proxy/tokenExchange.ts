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

import { createHash, timingSafeEqual } from 'node:crypto';
import * as config from '../config';

export type TokenExchangeResult =
  | { status: 'skipped' }
  | { status: 'exchanged'; authorization: string; internalUsername: string }
  | { status: 'rejected'; message: string };

const unrecognizedCredentialMessage =
  'Token exchange failed: credential not recognised by GitProxy';
const misconfiguredCredentialMessage =
  'Token exchange is misconfigured for this credential. Please contact an administrator.';

export const exchangeToken = (authorization: string | undefined): TokenExchangeResult => {
  const tokenExchange = config.getTokenExchange();
  if (!tokenExchange || tokenExchange.enabled !== true) {
    return { status: 'skipped' };
  }

  if (!authorization) {
    return { status: 'skipped' };
  }

  const basicMatch = /^Basic\s+([A-Za-z0-9+/]+={0,2})$/i.exec(authorization);
  if (!basicMatch) {
    return tokenExchange.allowUnmapped === true
      ? { status: 'skipped' }
      : { status: 'rejected', message: unrecognizedCredentialMessage };
  }

  const decoded = Buffer.from(basicMatch[1], 'base64').toString('utf8');
  const separatorIndex = decoded.indexOf(':');
  if (separatorIndex === -1) {
    return tokenExchange.allowUnmapped === true
      ? { status: 'skipped' }
      : { status: 'rejected', message: unrecognizedCredentialMessage };
  }

  const username = decoded.slice(0, separatorIndex);
  const token = decoded.slice(separatorIndex + 1);
  const tokenHash = createHash('sha256').update(token).digest();
  const mapping = tokenExchange.mappings?.find((candidate) => {
    if (candidate.externalUsername !== undefined && username !== candidate.externalUsername) {
      return false;
    }

    const expectedHash = Buffer.from(candidate.externalTokenSha256.toLowerCase(), 'hex');
    return expectedHash.length === tokenHash.length && timingSafeEqual(expectedHash, tokenHash);
  });

  if (!mapping) {
    return tokenExchange.allowUnmapped === true
      ? { status: 'skipped' }
      : { status: 'rejected', message: unrecognizedCredentialMessage };
  }

  const internalToken = process.env[mapping.internalTokenEnv];
  if (!internalToken) {
    console.error(
      `Token exchange is missing required environment variable ${mapping.internalTokenEnv}`,
    );
    return { status: 'rejected', message: misconfiguredCredentialMessage };
  }

  const internalUsername = mapping.internalUsername ?? username;
  const encodedCredentials = Buffer.from(`${internalUsername}:${internalToken}`).toString('base64');

  return {
    status: 'exchanged',
    authorization: `Basic ${encodedCredentials}`,
    internalUsername,
  };
};
