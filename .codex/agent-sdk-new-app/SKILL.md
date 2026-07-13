---
name: agent-sdk-new-app
description: >-
  Create and set up a new Claude Agent SDK application (TypeScript or Python). Use when the
  user asks to scaffold, bootstrap, or start a new Claude Agent SDK app/project.
disable-model-invocation: true
---

# Create a New Claude Agent SDK App

Migrated from the Claude Code `agent-sdk-dev` plugin's `/new-sdk-app` command.

## Reference Documentation

Before starting, fetch the official docs to ensure accurate, up-to-date guidance:

1. Overview: https://docs.claude.com/en/api/agent-sdk/overview
2. Based on the user's language choice:
   - TypeScript: https://docs.claude.com/en/api/agent-sdk/typescript
   - Python: https://docs.claude.com/en/api/agent-sdk/python
3. Relevant guides linked from the overview (streaming vs single mode, permissions, custom tools, MCP integration, subagents, sessions) based on the user's needs.

Always verify the latest package versions with WebSearch/WebFetch before installing anything — do not rely on training-data version numbers.

## Gather Requirements

Ask these questions **one at a time**, waiting for the user's answer before asking the next (skip any already answered):

1. **Language**: "Would you like to use TypeScript or Python?"
2. **Project name**: "What would you like to name your project?" (skip if provided as an argument)
3. **Agent type** (skip if #2 was detailed enough): coding agent (SRE, security review, code review), business agent (customer support, content creation), or custom/describe.
4. **Starting point**: minimal "Hello World", a basic agent with common features, or a specific example for their use case.
5. **Tooling choice**: state which package manager/tools you plan to use and confirm (e.g. respect a preference for pnpm/bun over npm).

Only after all questions are answered, propose the setup plan.

## Setup Plan

1. **Project initialization**
   - Create the project directory if needed.
   - TypeScript: `npm init -y`, set `"type": "module"` in `package.json`, add scripts including `typecheck`; create `tsconfig.json` suited to the SDK.
   - Python: create `requirements.txt` or `poetry init`.
2. **Check latest versions** before installing — TypeScript: https://www.npmjs.com/package/@anthropic-ai/claude-agent-sdk, Python: https://pypi.org/project/claude-agent-sdk/. Tell the user which version you're installing.
3. **SDK installation**
   - TypeScript: `npm install @anthropic-ai/claude-agent-sdk@latest`
   - Python: `pip install claude-agent-sdk`
   - Verify the installed version afterwards and report it.
4. **Starter files** — `index.ts`/`src/index.ts` or `main.py` with a basic query example, proper imports, and basic error handling using modern SDK syntax.
5. **Environment setup** — `.env.example` with `ANTHROPIC_API_KEY=your_api_key_here`, add `.env` to `.gitignore`, explain how to get a key from https://console.anthropic.com/.
6. **Optional extras** — offer to scaffold a Cursor project skill (`.cursor/skills/`) or an `AGENTS.md` entry for this new app if the user wants reusable agent instructions/subagents for it.

## Implementation

1. Confirm the plan with the user, then execute it end-to-end (create files, install deps with latest stable versions, verify installed versions).
2. Build a working example matching their agent type, with explanatory comments.
3. **Verify before finishing**:
   - TypeScript: run `npx tsc --noEmit`; fix ALL type errors until it passes cleanly.
   - Python: verify imports and check for syntax errors.
   - Do not consider the task done until verification passes.

## Verification

After setup, validate the app against SDK docs and best practices:

- TypeScript projects: read and follow the `agent-sdk-verifier-ts` skill (or dispatch it via the Task tool as a `generalPurpose` subagent) to produce a verification report.
- Python projects: read and follow the `agent-sdk-verifier-py` skill the same way.

Review the report and fix any critical issues before telling the user setup is complete.

## Getting Started Guide

Once verified, give the user:

1. **Next steps** — how to set the API key, how to run the app (`npm start` / `node --loader ts-node/esm index.ts` or `python main.py`).
2. **Resources** — links to the TypeScript/Python SDK references; explain system prompts, permissions, tools, MCP servers.
3. **Common next steps** — customizing the system prompt, adding custom tools via MCP, configuring permissions, creating subagents.

## Important Notes

- Always use the latest package versions; verify via WebSearch/PyPI/npm before installing.
- Never mark the task complete until type-checking (TS) or import/syntax validation (Python) passes.
- Check for existing files/directories before creating them; respect the user's preferred package manager.
- Ask setup questions one at a time, not all at once.
