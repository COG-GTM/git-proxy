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
 * protectBranches (push plugin)
 *
 * Blocks direct pushes (including deletions) to protected branches. Developers push a feature
 * branch through GitProxy and open a GitLab merge request instead.
 *
 * Configuration (environment variables, read on every push):
 *   GITPROXY_PROTECTED_BRANCHES  comma separated globs, default: main,master,release/*
 *                                `*` matches within one path segment, `**` across segments.
 */

// Peer dependencies; these resolve from the Node module path when @finos/git-proxy is installed
import { PushActionPlugin } from '@finos/git-proxy/plugin';
import { Step } from '@finos/git-proxy/proxy/actions';

import {
  DEFAULT_PROTECTED_BRANCHES,
  branchName,
  matchProtectedBranch,
  parseList,
} from './lib/policies.js';

export const STEP_NAME = 'protectBranches';

/**
 * @param {object} _req Express Request object
 * @param {object} action GitProxy Action
 * @return {Promise<object>} the Action, with an error step added for protected branches
 */
export async function protectBranches(_req, action) {
  const step = new Step(STEP_NAME);
  const patterns = parseList(process.env.GITPROXY_PROTECTED_BRANCHES, DEFAULT_PROTECTED_BRANCHES);
  const branch = branchName(action.branch);
  const matched = matchProtectedBranch(action.branch, patterns);

  if (matched) {
    step.setError(
      '\n\nYour push has been blocked by policy "protectBranches".\n' +
        `"${branch}" is a protected branch (matches "${matched}"); direct pushes are not allowed.\n` +
        'Push a feature branch instead and open a GitLab merge request, e.g.\n' +
        `  git push proxy HEAD:refs/heads/feature/PAY-123-short-description\n`,
    );
  } else {
    step.log(`Branch "${branch}" is not protected (${patterns.join(', ')}).`);
  }

  action.addStep(step);
  return action;
}

class ProtectBranchesPlugin extends PushActionPlugin {
  constructor() {
    super(protectBranches);
  }
}

export default new ProtectBranchesPlugin();
