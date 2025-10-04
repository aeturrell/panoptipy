# panoptipy

A Package for the Static Code Quality Assessment of Python codebases. It scans local codebases or remote GitHub repositories and generates a report summarising various code quality metrics.

![SVG logo of panoptipy](docs/logo.svg)

[![PyPI](https://img.shields.io/pypi/v/panoptipy.svg)](https://pypi.org/project/panoptipy/)
[![Status](https://img.shields.io/pypi/status/panoptipy.svg)](https://pypi.org/project/panoptipy/)
[![Python Version](https://img.shields.io/pypi/pyversions/panoptipy)](https://pypi.org/project/panoptipy)
[![License](https://img.shields.io/pypi/l/panoptipy)](https://opensource.org/licenses/MIT)
[![Read the documentation at https://aeturrell.github.io/panoptipy/](https://img.shields.io/badge/Go%20to%20the%20docs-purple?style=flat)](https://aeturrell.github.io/panoptipy/)
[![Tests](https://github.com/aeturrell/panoptipy/workflows/Tests/badge.svg)](https://github.com/aeturrell/panoptipy/actions?workflow=Tests)
[![Codecov](https://codecov.io/gh/aeturrell/panoptipy/branch/main/graph/badge.svg)](https://codecov.io/gh/aeturrell/panoptipy)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Downloads](https://static.pepy.tech/badge/panoptipy)](https://pepy.tech/projects/panoptipy)
[![Source](https://img.shields.io/badge/source%20code-github-lightgrey?style=for-the-badge)](https://github.com/aeturrell/panoptipy)

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![macOS](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)


## Quickstart

The main way to use **panoptipy** is through its command-line interface. Here's how to scan a Python codebase that is in the "project" directory:

```bash
# Basic scan with default settings
$ panoptipy scan /path/to/project
```

To run on multiple directories, you can specify them as a space-separated list:

```bash
# Scan multiple directories
$ panoptipy scan /path/to/project1 /path/to/project2
```

You can also use wildcards to specify directories:

```bash
# Scan all directories in the current directory
$ panoptipy scan ./*
```

Using the `scan` command in this way will:

- Load *all* configured checks (there's a list below)
- Analyse your codebase
- Generate a report with the results
- Output the report to the console (by default)

The scan report shows:

- Overall codebase rating (Gold, Silver, Bronze, or Problematic)
- A summary of whether each individual check passed or not
- Detailed information about any failures

## What is **panoptipy** for?

There is a lot of overlap between **panoptipy** and **pre-commit** (with the relevant hooks). So what are the differences?

- **pre-commit** is meant to be used by developers to check their own code before they commit it or in Continuous Integration (CI) / Continous Deployment (CD) pipelines.
- **panoptipy** has features that help the leaders and managers of other developers. To that end it can summarise the results of many code repos at once, eg:
  - all those written by a (GitHub) team
  - all those by a specific (GitHub) user
- **panoptipy** can be be used to generate and export reports in a variety of formats (JSON, parquet) for further analysis.

These packages are similar in that they can both be used in CI/CD pipelines but **pre-commit** should be your first port of call for that and is not only more geared to that use, but also *far* more mature.

## Installation

You can use **panoptipy** as a stand-alone tool via [Astral's uv](https://docs.astral.sh/uv/) package:

```bash
uvx panoptipy scan .
```

Alternatively, you can install it as a Python package with `pip install` or `uv add`.

To install the development version from git, use:

```bash
pip install git+https://github.com/aeturrell/panoptipy.git
```

## Documentation

You can find the full documentation for **panoptipy** at [https://aeturrell.github.io/panoptipy/](https://aeturrell.github.io/panoptipy/).
