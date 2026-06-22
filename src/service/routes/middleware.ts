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

import { Request, Response, NextFunction } from 'express';

/**
 * Reject unauthenticated requests. Accepts either a passport session
 * (req.isAuthenticated()) or a request that a prior auth handler (e.g. JWT)
 * has populated with req.user.
 */
export const ensureAuthenticated = (req: Request, res: Response, next: NextFunction): void => {
  const sessionAuthed = typeof req.isAuthenticated === 'function' && req.isAuthenticated();
  if (sessionAuthed || req.user) {
    return next();
  }
  res.status(401).send({ message: 'Authentication required' });
};
