# SafePatch

SafePatch is a deterministic safety gate for AI coding agents. It treats task
plans and repository content as untrusted input, scans them before execution,
requires approval for reviewable actions, runs only explicit `argv` commands,
and produces a tamper-evident proof report.

## Why it exists

AI coding agents can accidentally run destructive commands, follow prompt
injection hidden in a README, expose credentials, or claim success after a
timed-out action. SafePatch keeps the model (or agent) in the proposal role and
makes the application own policy, approval, execution, and evidence.

## Current MVP

- Repository inventory with SHA-256 file hashes
- Dangerous-command detection: destructive operations, privilege escalation,
  remote scripts, external side effects, credential access, shell operators
- Secret detection with redacted evidence
- Prompt-injection detection in repository text and task text
- Repository-boundary and symlink checks
- Structured `argv` execution only; no `shell=True`
- Human approval tied to the exact plan, command, and repository snapshot
- Sanitized output, timeouts, explicit `unknown` execution state, and proof reports
- JSON report verification through a report hash

SafePatch is intentionally offline and standard-library-only in this first
version. It does not require an API key, paid service, database, or model
download.

## Quick start

From the repository root:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m safepatch scan \
  --repo examples/demo_repo \
  --plan examples/clean_plan.json \
  --report artifacts/demo-report.json
```

The example scan writes:

- `artifacts/demo-report.json` — machine-readable evidence
- `artifacts/demo-report.md` — human-readable evidence

The CLI intentionally exits with code `2` when it finds a blocked command.
That is a reportable policy result, not a crash.

## Browser demo

SafePatch includes a dependency-free browser demo backed by the real scanning,
approval, execution, and report-verification workflow. From the repository root,
start the loopback-only server:

```bash
PYTHONPATH=src python3 -m safepatch web
```

Open <http://127.0.0.1:8765>. Choose the clean test plan or the risky installer
plan, then click **Run demo scan**. The clean plan lets you run the example test
command after scanning; the risky plan shows how SafePatch blocks a remote shell
installer without executing it. Use **Verify hash** to check the report's
tamper-evident hash. Stop the server with `Ctrl+C`.

The demo intentionally uses only the allowlisted `examples/demo_repo` and the
two checked-in example plans. It binds to `127.0.0.1` by default and stores its
temporary reports outside the repository.

## Deploy to Render

The repository includes a pinned Docker image definition and a Render Blueprint.
After pushing the repository to GitHub:

1. Open the [Render Dashboard](https://dashboard.render.com/).
2. Choose **New → Blueprint** and select this repository.
3. Confirm the `safepatch-demo` web service from `render.yaml` and deploy it.

Render builds `Dockerfile`, binds the service to `0.0.0.0`, uses Render's `PORT`
value, and checks `/` for health. The Blueprint uses the free plan and deploys
only the checked-in demo data; it does not require an API key or database.

For a local container smoke test:

```bash
docker build -t safepatch-demo .
docker run --rm -p 10000:10000 -e PORT=10000 safepatch-demo
```

Open <http://127.0.0.1:10000> after the container starts.

## Safe command workflow

`scan` never executes a command:

```bash
PYTHONPATH=src python3 -m safepatch scan \
  --repo examples/demo_repo \
  --plan examples/clean_plan.json
```

Reviewable commands require approval tied to the exact scan:

```bash
PYTHONPATH=src python3 -m safepatch approve \
  --report artifacts/report.json \
  --command tests
```

After approval, run the command:

```bash
PYTHONPATH=src python3 -m safepatch run \
  --report artifacts/report.json \
  --command tests
```

You can verify that a report has not been modified:

```bash
PYTHONPATH=src python3 -m safepatch verify \
  --report artifacts/report.json
```

## Plan format

Plans use explicit argument arrays. Shell command strings are analyzed but
blocked from execution:

```json
{
  "task": "Run the repository tests and summarize failures.",
  "commands": [
    {
      "id": "tests",
      "argv": ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"],
      "cwd": ".",
      "reason": "Verify the requested change"
    }
  ]
}
```

## Trust boundaries

SafePatch does not claim that a repository is safe. It reports evidence from a
bounded, deterministic scan. A future model adapter can explain findings, but
it must not replace the deterministic policy gate.

The first demo flow is:

1. Scan a repository and an agent-generated plan.
2. Block a remote installer or credential access attempt.
3. Approve a local test command.
4. Execute it without a shell and capture sanitized output.
5. Verify the proof report.

## Development

The project targets Python 3.11+ and has no runtime dependencies. Run the
standard-library test suite with:

```bash
python3 -m unittest discover -s tests -v
```
