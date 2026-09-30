# agent-governance

[![CI](https://github.com/balajeeasish/agent-governance/actions/workflows/ci.yml/badge.svg)](https://github.com/balajeeasish/agent-governance/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Policy checks, audit logging, and human review gates for AI agents - in pure Python, zero dependencies.**

## Why it matters

An AI agent that can run shell commands, write files, and call external APIs is powerful and dangerous in equal measure. Before you give an agent real tools, you need three things: a way to say what is allowed, a record of everything it tried, and a human in the loop for the risky calls. This library gives you all three in a few hundred lines of readable Python, with no third-party packages to audit.

## Quickstart

Runs in under a minute. Python 3.10 or newer, no dependencies to install.

```bash
git clone https://github.com/balajeeasish/agent-governance.git
cd agent-governance
python examples/demo.py
```

Run the test suite:

```bash
python -m pytest -q
```
