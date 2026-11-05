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
import { getUsers, isUserPushAllowed } from '../../../db';
import { User } from '../../../db/types';
import { getAuthenticatedGitAccount } from '../pusherIdentity';

// Execute if the repo is approved
const exec = async (req: Request, action: Action): Promise<Action> => {
  const step = new Step('checkUserPushPermission');

  // The pusher is identified from the credentials presented to the proxy, never from
  // commit metadata in the pack, which the client fully controls.
  const gitAccount = await getAuthenticatedGitAccount(action.url, req.headers?.authorization, step);

  if (!gitAccount) {
    step.setError(
      'Push blocked: Unable to authenticate the pusher. Please make sure your git credentials are valid.',
    );
    action.addStep(step);
    step.error = true;
    return action;
  }

  return await validateUser(gitAccount, action, step);
};

/**
 * Finds the GitProxy users linked to an SCM account.
 * @param {string} gitAccount The authenticated SCM account
 * @return {Promise<User[]>} The matching users
 */
const findUsersByGitAccount = async (gitAccount: string): Promise<User[]> =>
  (await getUsers()).filter((user) => user.gitAccount?.toLowerCase() === gitAccount.toLowerCase());

/**
 * Helper that validates the user's push permission.
 * This can be used by other actions that need it.
 * @param {string} gitAccount The authenticated SCM account of the pusher
 * @param {Action} action The action object
 * @param {Step} step The step object
 * @return {Promise<Action>} The action object
 */
const validateUser = async (gitAccount: string, action: Action, step: Step): Promise<Action> => {
  let isUserAllowed = false;

  // Find the GitProxy user linked to this SCM account
  const list = await findUsersByGitAccount(gitAccount);

  if (list.length > 1) {
    step.error = true;
    step.log(
      `Multiple Users have git account ${gitAccount} so we cannot uniquely identify the user, ending`,
    );

    step.setError(
      `Your push has been blocked (there are multiple users with git account ${gitAccount})`,
    );
    action.addStep(step);
    return action;
  } else if (list.length == 0) {
    step.log(`No user with git account ${gitAccount} found`);
  } else {
    action.user = list[0].username;
    action.userEmail = list[0].email;
    step.log(`Push authenticated as user ${list[0].username} (git account ${gitAccount})`);
    isUserAllowed = await isUserPushAllowed(action.url, list[0].username);
  }

  step.log(`User ${gitAccount} permission on Repo ${action.url}: ${isUserAllowed}`);

  if (!isUserAllowed) {
    step.error = true;
    step.log(`User ${gitAccount} is not allowed to push on repo ${action.url}, ending`);
    step.setError(
      `Your push has been blocked (${gitAccount} ` +
        `is not allowed to push on repo ` +
        `${action.url})`,
    );
    action.addStep(step);
    return action;
  }

  step.log(`User ${gitAccount} is allowed to push on repo ${action.url}`);
  action.addStep(step);
  return action;
};

exec.displayName = 'checkUserPushPermission.exec';

export { exec, validateUser, findUsersByGitAccount };
