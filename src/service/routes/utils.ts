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

import { Request } from 'express';
import { PublicUser, QueryValue, User as DbUser } from '../../db/types';

interface User extends Express.User {
  username: string;
  admin?: boolean;
}

export function isAdminUser(user?: Express.User): user is User & { admin: true } {
  return user !== null && user !== undefined && (user as User).admin === true;
}

/**
 * Builds a database filter from a request query string. Only allowlisted keys
 * with plain string values are kept; operator keys (`$...`), dotted paths,
 * arrays and nested objects are dropped so callers cannot inject query
 * operators. `"true"`/`"false"` are coerced to booleans.
 */
export const buildQueryFilter = <T extends Record<string, QueryValue>>(
  rawQuery: Request['query'],
  allowedKeys: readonly (keyof T & string)[],
): Partial<T> => {
  const filter: Partial<T> = {};

  for (const key of Object.keys(rawQuery)) {
    if (key.startsWith('$') || key.includes('.')) continue;
    if (!allowedKeys.includes(key)) continue;

    const rawValue = rawQuery[key];
    if (typeof rawValue !== 'string') continue;

    let value: QueryValue = rawValue;
    if (rawValue === 'true') value = true;
    if (rawValue === 'false') value = false;
    filter[key as keyof T] = value as T[keyof T];
  }

  return filter;
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
