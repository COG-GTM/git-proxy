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

// GitProxy refuses to start with the insecure built-in default cookieSecret.
// Tests that start the service (via Service.start) rely on a configured secret,
// so provide one before any module reads process.env. Tests that explicitly
// exercise cookieSecret resolution (e.g. test/testConfig.test.ts) clear this in
// their own setup.
process.env.GIT_PROXY_COOKIE_SECRET = process.env.GIT_PROXY_COOKIE_SECRET || 'test-cookie-secret';
