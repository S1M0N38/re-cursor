# re-cursor



https://github.com/user-attachments/assets/9cd60104-45e9-4e52-9e7d-1378615d3f5d



A toolkit for reverse engineering, analyzing, and understanding API requests made by Cursor and similar AI code assistants.

## Overview

re-cursor provides a collection of mitmproxy scripts for intercepting, analyzing, and reproducing HTTP requests made by AI coding assistants. The toolkit is designed to help researchers and developers understand the underlying API communication patterns.

## Project Structure

```
re-cursor/
├── data/                  # Directory for storing captured request/response data
│   └── <domain>/          # Organized by domain (created automatically)
├── data_redacted/         # Directory for storing redacted copies of captured data
├── scripts/               # mitmproxy scripts for various analysis tasks
│   ├── dump_requests.py   # Script to capture and save HTTP flows as JSON
│   └── redact_sensitive_data.py # Script to create redacted copies of captured data
└── chat-completion-md/    # Submodule with test data (for testing purposes)
```

## Requirements

- Python 3.12+
- mitmproxy 11.1.3+

## Installation

1. Clone the repository with its submodules:

```bash
git clone --recurse-submodules https://github.com/S1M0N38/re-cursor.git
cd re-cursor
```

2. Install dependencies with uv:

```bash
uv venv
uv sync
```

## Usage

### Capturing API Requests

To capture requests and responses from Cursor or other applications:

1. Start mitmproxy with the dump_requests script:

```bash
mitmdump -s scripts/dump_requests.py
```

2. Configure your application to use the mitmproxy as a proxy (default: http://localhost:8080)

3. Use the application normally. All HTTP requests and responses will be captured and saved in the `data/` directory, organized by domain.

### Redacting Sensitive Data

To create redacted copies of captured data (removing authentication tokens, sensitive identifiers, etc.):

```bash
python scripts/redact_sensitive_data.py data
```

This will:
- Create a `data_redacted/` directory
- Process all JSON files in the `data/` directory and its subdirectories
- Create redacted versions that replace sensitive information with placeholders
- Preserve the original directory structure and files

The script redacts sensitive information based on:
- Known sensitive keys (authorization tokens, API keys, etc.)
- Pattern-based detection (UUIDs, JWT tokens, etc.)

Redacted files are safe to share or include in repositories without exposing sensitive information.
