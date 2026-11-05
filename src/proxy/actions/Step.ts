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

import { v4 as uuidv4 } from 'uuid';

const MAX_CONSOLE_MESSAGE_LENGTH = 200;

/**
 * Reduce a step message to a single short line for the process log.
 * Full messages (which may quote diffs or detected secrets) stay in the step record only.
 * @param {string} message The full step message
 * @return {string} The first non-empty line, truncated to MAX_CONSOLE_MESSAGE_LENGTH
 */
const summarizeForConsole = (message: string): string => {
  const firstLine = message.split('\n').find((line) => line.trim() !== '') ?? '';
  const trimmed = firstLine.trim();
  const summary =
    trimmed.length > MAX_CONSOLE_MESSAGE_LENGTH
      ? trimmed.slice(0, MAX_CONSOLE_MESSAGE_LENGTH)
      : trimmed;
  return summary.length < message.trim().length
    ? `${summary} [truncated, ${message.length} chars]`
    : summary;
};

export interface StepData {
  id: string;
  stepName: string;
  content: any;
  error: boolean;
  errorMessage: string | null;
  blocked: boolean;
  blockedMessage: string | null;
  logs: string[];
}

/** Class representing a Push Step. */
class Step implements StepData {
  id: string;
  stepName: string;
  content: any;
  error: boolean;
  errorMessage: string | null;
  blocked: boolean;
  blockedMessage: string | null;
  logs: string[] = [];

  constructor(
    stepName: string,
    error: boolean = false,
    errorMessage: string | null = null,
    blocked: boolean = false,
    blockedMessage: string | null = null,
    content: any = null,
  ) {
    this.id = uuidv4();
    this.stepName = stepName;
    this.content = content;
    this.error = error;
    this.errorMessage = errorMessage;
    this.blocked = blocked;
    this.blockedMessage = blockedMessage;
  }

  setError(message: string): void {
    this.error = true;
    this.errorMessage = message;
    this.log(message);
  }

  setContent(content: any): void {
    this.content = content;
  }

  setAsyncBlock(message: string): void {
    this.blocked = true;
    this.blockedMessage = message;
  }

  log(message: string): void {
    const text = String(message);
    this.logs.push(`${this.stepName} - ${text}`);
    console.info(`${this.stepName} - ${summarizeForConsole(text)}`);
  }
}

export { Step };
