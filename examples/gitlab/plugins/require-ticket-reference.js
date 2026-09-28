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
 * requireTicketReference (push plugin)
 *
 * Every commit in a push must reference a ticket: a Jira key such as PAY-123 or a GitLab issue
 * such as #42 / group/project#42. Merge commits created by git or by a GitLab MR merge are exempt.
 *
 * Configuration (environment variables, read on every push):
 *   GITPROXY_TICKET_PATTERN  regular expression source, default: \b[A-Z][A-Z0-9]+-\d+\b|#\d+\b
 */

// Peer dependencies; these resolve from the Node module path when @finos/git-proxy is installed
import { PushActionPlugin } from '@finos/git-proxy/plugin';
import { Step } from '@finos/git-proxy/proxy/actions';

import { DEFAULT_TICKET_PATTERN, findCommitsMissingTicket, subjectLine } from './lib/policies.js';

export const STEP_NAME = 'requireTicketReference';

/**
 * @param {object} _req Express Request object
 * @param {object} action GitProxy Action
 * @return {Promise<object>} the Action, with an error step added when a commit lacks a ticket
 */
export async function requireTicketReference(_req, action) {
  const step = new Step(STEP_NAME);
  const pattern = process.env.GITPROXY_TICKET_PATTERN || DEFAULT_TICKET_PATTERN;
  const offending = findCommitsMissingTicket(action.commitData, pattern);

  if (offending.length > 0) {
    const list = offending
      .map((commit) => `  - "${subjectLine(commit.message)}" <${commit.authorEmail}>`)
      .join('\n');
    step.setError(
      '\n\nYour push has been blocked by policy "requireTicketReference".\n' +
        'Every commit message must reference a ticket, e.g. "PAY-123: ..." (Jira) or "... #42" (GitLab issue).\n' +
        `Commits without a ticket reference:\n${list}\n` +
        'Reword them with `git rebase -i` (or `git commit --amend`) and push again.\n',
    );
  } else {
    step.log(`All ${action.commitData?.length ?? 0} commit(s) reference a ticket.`);
  }

  action.addStep(step);
  return action;
}

class RequireTicketReferencePlugin extends PushActionPlugin {
  constructor() {
    super(requireTicketReference);
  }
}

export default new RequireTicketReferencePlugin();
