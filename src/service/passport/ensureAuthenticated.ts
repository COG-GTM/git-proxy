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

import type { Request, Response, NextFunction } from 'express';

/**
 * Middleware that allows the request to proceed only when it is authenticated,
 * either via a JWT (which populates `req.user`) or via an established session
 * (`req.isAuthenticated()`). Otherwise it responds with 401.
 */
export const ensureAuthenticated = (req: Request, res: Response, next: NextFunction): void => {
  if (req.user || (typeof req.isAuthenticated === 'function' && req.isAuthenticated())) {
    return next();
  }

  res.status(401).send('Authentication required\n');
};
