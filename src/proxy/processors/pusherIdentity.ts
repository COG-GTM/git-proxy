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

import axios from 'axios';
import { Step } from '../actions';
import { getErrorMessage } from '../../utils/errors';

const IDENTITY_LOOKUP_TIMEOUT_MS = 10000;

export type BasicCredentials = { username: string; password: string };

/**
 * Parses an HTTP Basic `Authorization` header as sent by git clients.
 * @param {string | undefined} header The raw Authorization header
 * @return {BasicCredentials | null} The credentials, or null if missing or malformed
 */
export const parseBasicAuth = (header?: string): BasicCredentials | null => {
  if (!header) return null;
  const [scheme, encoded] = header.trim().split(/\s+/);
  if (!scheme || scheme.toLowerCase() !== 'basic' || !encoded) return null;

  const decoded = Buffer.from(encoded, 'base64').toString('utf8');
  const separator = decoded.indexOf(':');
  if (separator < 0) return null;

  const username = decoded.slice(0, separator);
  const password = decoded.slice(separator + 1);
  if (!password) return null;
  return { username, password };
};

/**
 * Resolves the SCM account that owns the credentials presented to the proxy.
 *
 * GitHub and GitLab accept any username alongside a token, so the account is
 * resolved by asking the provider who the token belongs to. Other git servers
 * authenticate the username and password together, so the username is used.
 * @param {string} url The upstream repository URL
 * @param {string | undefined} authHeader The Authorization header sent by the git client
 * @param {Step} step The step used for logging
 * @return {Promise<string | null>} The authenticated SCM account, or null if it cannot be established
 */
export const getAuthenticatedGitAccount = async (
  url: string,
  authHeader: string | undefined,
  step: Step,
): Promise<string | null> => {
  const credentials = parseBasicAuth(authHeader);
  if (!credentials) {
    step.log('No valid Basic Authorization header was provided with the push');
    return null;
  }

  let upstream: URL;
  try {
    upstream = new URL(url);
  } catch {
    step.log(`Unable to parse upstream URL ${url}`);
    return null;
  }

  const hostname = upstream.hostname.toLowerCase();
  const headers = {
    Authorization: `Bearer ${credentials.password}`,
    Accept: 'application/json',
    'User-Agent': 'git-proxy',
  };

  try {
    if (hostname === 'github.com') {
      const { data } = await axios.get<{ login?: string }>('https://api.github.com/user', {
        headers,
        timeout: IDENTITY_LOOKUP_TIMEOUT_MS,
      });
      return data?.login || null;
    }

    if (hostname.includes('gitlab')) {
      const { data } = await axios.get<{ username?: string }>(
        `${upstream.protocol}//${upstream.host}/api/v4/user`,
        { headers, timeout: IDENTITY_LOOKUP_TIMEOUT_MS },
      );
      return data?.username || null;
    }
  } catch (error: unknown) {
    step.log(`Unable to resolve the account for the push credentials: ${getErrorMessage(error)}`);
    return null;
  }

  return credentials.username || null;
};
