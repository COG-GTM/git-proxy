# GitProxy security model

Status: drafted from the code, with the user's answers folded in. **User:** marks what the user said. **(assumed)** marks my reading of the code. `SECURITY.md` is only a disclosure policy (FINOS CVE process). It does not describe a security model.

## System overview

GitProxy (`@finos/git-proxy` 2.0.0) is a Node/Express HTTP(S) proxy in front of upstream Git hosts (GitHub by default). Developers point their remotes at the proxy. Every `git push` runs a policy chain before anything reaches upstream. A push that passes the checks waits for a human approver ("authoriser") to approve it in the web UI. Once approved, the developer pushes again and that push is forwarded. Fetches/pulls only check that the repo is on the authorised list.

**(assumed)** It is deployed inside the corporate network as the mandatory egress path for pushes to external Git hosts. The only deployment artefacts are `Dockerfile` (node:24, runs as UID 1000 under tini, exposes 8000/8080/8444) and `docker-compose.yml` (e2e: proxy, Mongo 7, local git server). **User:** there is no infra repo, so the threat model works from the Dockerfile and compose file only. Ingress, TLS termination and network policy are unknown.

## Components

| Name                        | Code                                                                                                                                         | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Git Proxy**               | `src/proxy/index.ts`, `src/proxy/routes/` (helper.ts, index.ts), `src/proxy/processors/pre-processor/parseAction.ts`                         | Receives git smart-HTTP on :8000 (HTTPS :8443 when `tls.enabled`) and forwards it to upstream via `express-http-proxy`. The upstream host is derived from the URL path (`/<host>/<owner>/<repo>.git`), with a fallback to github.com                                                                                                                                                                                                                              |
| **Push Policy Chain**       | `src/proxy/chain.ts`, `src/proxy/processors/push-action/*`, `src/proxy/processors/post-processor/*`, `src/proxy/actions/*`                   | parsePush → checkEmptyBranch → checkRepoInAuthorisedList → checkCommitMessages → checkAuthorEmails → checkUserPushPermission → pullRemote → writePack → checkHiddenCommits → checkIfWaitingAuth → preReceive → getDiff → gitleaks → scanDiff → blockForAuth, then audit and auto-approve/reject. Clones upstream into `./.remote/<id>` with the pusher's Basic-auth credentials. Runs `git`, `gitleaks` (`spawn` with `shell: true`) and `./hooks/pre-receive.sh` |
| **Admin API**               | `src/service/index.ts`, `src/service/routes/` (push.ts, repo.ts, users.ts, config.ts, home.ts, healthcheck.ts)                               | Express API on :8080 (HTTPS :8444). Session cookies, lusca CSRF (disabled when `NODE_ENV=test`), rate limiting, CORS from `ALLOWED_ORIGINS`. Approve/reject/cancel pushes. Admins manage repos, the authorised list and user permissions                                                                                                                                                                                                                          |
| **Authentication**          | `src/service/passport/` (local.ts, activeDirectory.ts, ldaphelper.ts, oidc.ts, jwtAuthHandler.ts, jwtUtils.ts), `src/service/routes/auth.ts` | Local (bcrypt), Active Directory/LDAP, OIDC login, optional JWT bearer auth for the API with role mapping. `isAdminUser` checks `user.admin === true`                                                                                                                                                                                                                                                                                                             |
| **Data Store**              | `src/db/` (file/ = NeDB under `./.data/db`, mongo/)                                                                                          | Users (password hashes, gitAccount, admin flag), repos (canPush/canAuthorise lists), pushes/audit (diffs, commit data, attestations), sessions                                                                                                                                                                                                                                                                                                                    |
| **Configuration & Plugins** | `src/config/` (ConfigLoader.ts, file.ts, env.ts), `src/plugin.ts`, `proxy.config.json`, `config.schema.json`                                 | Config file plus optional remote config sources (file/http/git, polled). Plugins are loaded as npm/JS modules into the chain                                                                                                                                                                                                                                                                                                                                      |
| **Web UI**                  | `src/ui/`                                                                                                                                    | React SPA served by the Admin API. Push review, attestation, repo and user management                                                                                                                                                                                                                                                                                                                                                                             |
| **Docs Website**            | `website/`                                                                                                                                   | Docusaurus docs site (static). In scope per user                                                                                                                                                                                                                                                                                                                                                                                                                  |
| **CLI**                     | `packages/git-proxy-cli/`                                                                                                                    | Authenticates to the API and approves/rejects/cancels pushes                                                                                                                                                                                                                                                                                                                                                                                                      |

## Trust boundaries & entry points

1. **Developer → Git Proxy (:8000/:8443).** Anyone with network access to the proxy **(assumed: all corporate developers)**. Pushes are attributed by commit **author email** (`action.userEmail`, which the pusher controls), which is matched to a GitProxy user. The pusher's upstream credentials arrive in the `Authorization` header and are reused by `pullRemote`.
2. **Browser/CLI → Admin API (:8080/:8444).** Unauthenticated endpoints include `/api/auth/*` (login, OIDC callback), `/api/v1/healthcheck` and `/api/v1/config/*`. `/api/v1/push|repo|user` sit behind `jwtAuthHandler`, which is a pass-through when API JWT auth is disabled (the default). Each route then checks `req.user` / `isAdminUser` itself.
3. **GitProxy → upstream Git hosts.** Outbound clone and forward. The upstream host comes from the request path.
4. **GitProxy → identity providers** (AD/LDAP, OIDC issuer, JWKS) and **→ remote config sources** (http/git).
5. **GitProxy → local OS.** Child processes (git, gitleaks, pre-receive hook) run on attacker-supplied repo content in `./.remote`.

## Assets

**User:** all assets below matter equally. None is ranked above the others.

- **Integrity of the push gate.** Nothing reaches an upstream repo without passing the chain and receiving approval from someone other than the author. The repos at stake hold the organisation's code, IP and secrets.
- **Pusher credentials (PATs/passwords)** carried through the proxy in Basic auth.
- **Admin / authoriser privileges** (the admin flag and canAuthorise lists), the authorised repo list and user accounts.
- **Audit records** (push diffs, attestations), used as compliance evidence.
- **Secrets in config:** `cookieSecret`, AD bind password, OIDC client secret, remote-config tokens.
- **Host integrity** of the proxy server: command execution there exposes all of the above.

## Attackers that matter

**User:** these attackers matter:

- **Malicious or careless insider developer** who pushes through the proxy, can reach its ports, and may hold a low-privilege UI account. Wants to push unapproved code or secrets upstream, approve their own push, or escalate to admin.
- **Authenticated low-privilege UI user** who targets other users' accounts, pushes, credentials or the admin functions.

Insider developers are on the corporate network. So "unauthenticated" API/proxy issues they can reach are in scope through them. An attack that needs an outside party (external internet attacker, compromised upstream host or IdP, a victim browsing a malicious external site with no insider involved) is not one of the named attackers.

## Existing controls

- Push chain checks (authorised list, commit message and author email rules, per-repo `canPush`, hidden-commit check, gitleaks, diff scan) plus manual approval with attestation (`src/service/routes/push.ts`). Self-approval is blocked unless the approver is an admin.
- `processGitUrl` caps URL length at 512 characters (ReDoS guard). The concurrent-push folder check is in `pullRemote`.
- bcrypt passwords. Mongo user queries project out `password`. `toPublicUser` strips sensitive fields.
- lusca CSRF/HSTS/nosniff/xframe, `express-rate-limit`, httpOnly session cookies, `trust proxy` 1.
- Docker image runs as a non-root UID. CI has CodeQL, dependency-review and Scorecard.

## Out of scope / accepted risk

**User:** out of scope:

- `experimental/`
- `plugins/git-proxy-plugin-samples/`
- test and Cypress fixtures (`test/`, `cypress/`, `localgit/`, e2e configs such as `test-e2e.proxy.config.json`, `docker-compose.yml` test services)
- the dev-only defaults in `proxy.config.json` (e.g. `cookieSecret: "cookie secret"`, default local users). Production is assumed to override these.

**User:** `website/` (Docusaurus docs site) stays in scope.

## Open questions

1. Is the UI/API reachable from outside the corporate network? (No infra repo exists to answer this.)
2. Which auth mode runs in production (local, AD, OIDC, JWT for the API)?
3. Is the file (NeDB) or the Mongo sink used in production?
