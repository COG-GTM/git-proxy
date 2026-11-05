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

import { Action, Step } from '../../actions';
import { getAuthenticatedGitAccount } from '../pusherIdentity';
import { findUsersByGitAccount } from './checkUserPushPermission';

// Records the authenticated pusher on the action so that push plugins, which run right
// after this step, see a trusted identity. Never blocks: checkUserPushPermission enforces.
const exec = async (req: Request, action: Action): Promise<Action> => {
  const step = new Step('resolvePusher');

  const gitAccount = await getAuthenticatedGitAccount(action.url, req.headers?.authorization, step);
  if (gitAccount) {
    const list = await findUsersByGitAccount(gitAccount);
    if (list.length === 1) {
      action.user = list[0].username;
      action.userEmail = list[0].email;
      step.log(`Push authenticated as user ${list[0].username} (git account ${gitAccount})`);
    } else {
      step.log(`Found ${list.length} users with git account ${gitAccount}`);
    }
  }

  action.addStep(step);
  return action;
};

exec.displayName = 'resolvePusher.exec';

export { exec };
