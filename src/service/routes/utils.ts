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

import { ParsedQs } from 'qs';
import { PublicUser, QueryValue, User as DbUser } from '../../db/types';

interface User extends Express.User {
  username: string;
  admin?: boolean;
}

export function isAdminUser(user?: Express.User): user is User & { admin: true } {
  return user !== null && user !== undefined && (user as User).admin === true;
}

/**
 * Build a database query from a request query string, accepting only keys
 * present in the given allowlist. Unknown keys, operator keys (`$...`), dotted
 * paths and non-scalar values are silently ignored so that callers cannot
 * inject query operators or filter on unintended fields. Pagination
 * parameters (`limit`, `skip`) are not part of the query itself.
 */
export const buildQuery = <T extends Record<string, QueryValue>>(
  rawQuery: ParsedQs,
  allowedKeys: readonly string[],
): Partial<T> => {
  const query: Partial<T> = {};

  for (const key of Object.keys(rawQuery)) {
    if (!key) continue;
    if (key === 'limit' || key === 'skip') continue;
    if (key.startsWith('$') || key.includes('.')) continue;
    if (!allowedKeys.includes(key)) continue;

    const rawValue = rawQuery[key];
    if (typeof rawValue !== 'string') continue;

    let value: QueryValue = rawValue;
    if (rawValue === 'false') value = false;
    if (rawValue === 'true') value = true;

    query[key as keyof T] = value as T[keyof T];
  }

  return query;
};

export const toPublicUser = (user: DbUser): PublicUser => {
  return {
    username: user.username || '',
    displayName: user.displayName || '',
    email: user.email || '',
    title: user.title || '',
    gitAccount: user.gitAccount || '',
    admin: user.admin || false,
  };
};
