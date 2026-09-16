# Mistakes

## Coordinator E2E used the wrong human transport
**What happened:** The verification harness got 403/401 while the wrapper had registered successfully; these were harness failures, not proven integration defects.
**Root cause:** The coordinator assumed a browser session token used Bearer authentication and that human messages could use the agent-only `/api/send` endpoint.
**Prevention:** Read middleware and endpoint contracts first. Browser REST uses `X-Session-Token`; human messages use authenticated `/ws`. Keep agent registration Bearer tokens separate. After correcting the harness, the full room-to-A2A round trip passed.

## Coder handoff omitted absolute workspace
**What happened:** A correction run searched unrelated home directories rather than editing the target repo; coordinator stopped it before edits.
**Root cause:** Coordinator relied on `--in` and subprocess workdir to communicate the repository, but the worker's tools did not locate relative targets there. The prompt omitted the absolute path.
**Prevention:** Include absolute repository, target files, and test interpreter paths in every worker assignment. Require explicit terminal workdir and prohibit broad home-directory searches. Check early tool activity, not just process startup.

## Background handoff was not durable
**What happened:** The first launched coder run ended with termination_source=agent_close before finishing.
**Root cause:** A background terminal launch was treated as sufficient handoff without verifying its lifetime across session closure.
**Prevention:** Supervise the owning session, verify process state on resumption, and use a documented durable worker mechanism for work that must outlive it.
