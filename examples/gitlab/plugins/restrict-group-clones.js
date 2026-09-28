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

/**
 * restrictGroupClones (pull plugin)
 *
 * Logs every clone/fetch of a repository that lives under a restricted GitLab group and blocks it
 * unless the GitLab username sent by the git client (HTTP Basic auth) is on an allowlist.
 *
 * The username is asserted by the client and is not verified by GitProxy (GitLab validates the
 * PAT upstream). Treat this as an audit trail and a guard rail on top of GitLab group membership,
 * not as the primary access control.
 *
 * Configuration (environment variables, read on every fetch):
 *   GITPROXY_RESTRICTED_GROUPS         comma separated host/group[/subgroup] prefixes,
 *                                      e.g. gitlab.example.internal/security,gitlab.com/acme/secret
 *   GITPROXY_RESTRICTED_GROUP_READERS  comma separated GitLab usernames allowed to clone them
 */

// Peer dependencies; these resolve from the Node module path when @finos/git-proxy is installed
import { PullActionPlugin } from '@finos/git-proxy/plugin';
import { Step } from '@finos/git-proxy/proxy/actions';

import { basicAuthUsername, matchRestrictedGroup, parseList } from './lib/policies.js';

export const STEP_NAME = 'restrictGroupClones';

/**
 * @param {object} req Express Request object
 * @param {object} action GitProxy Action
 * @return {Promise<object>} the Action, with an error step added when the clone is not allowed
 */
export async function restrictGroupClones(req, action) {
  const step = new Step(STEP_NAME);
  const groups = parseList(process.env.GITPROXY_RESTRICTED_GROUPS);
  const readers = parseList(process.env.GITPROXY_RESTRICTED_GROUP_READERS).map((u) =>
    u.toLowerCase(),
  );
  const group = matchRestrictedGroup(action.url, groups);

  if (group) {
    const username = basicAuthUsername(req?.headers?.authorization);
    step.log(`Fetch of ${action.url} (restricted group ${group}) by ${username ?? 'anonymous'}`);

    if (!username || !readers.includes(username.toLowerCase())) {
      step.setError(
        `Clone/fetch blocked by policy "restrictGroupClones": ${group} is a restricted group ` +
          `and ${username ? `"${username}"` : 'anonymous access'} is not on the reader allowlist.`,
      );
    }
  }

  action.addStep(step);
  return action;
}

class RestrictGroupClonesPlugin extends PullActionPlugin {
  constructor() {
    super(restrictGroupClones);
  }
}

export default new RestrictGroupClonesPlugin();
