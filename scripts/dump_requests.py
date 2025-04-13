"""
Dump HTTP request and response payloads to JSON files.

This script intercepts HTTP flows and saves the request and response
payloads to JSON files in the data/ directory. Files are organized by
domain and include a timestamp in their names.

Usage:
    mitmdump -s scripts/dump_requests.py
"""

import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from mitmproxy import ctx, http


class DumpPayloads:
    """Addon to dump request and response payloads to JSON files."""

    def __init__(self):
        """Initialize the addon with the data directory path."""
        # Get the repo root directory
        self.repo_root = Path(__file__).resolve().parent.parent
        self.data_dir = self.repo_root / "data"
        self.ensure_data_dir()
        ctx.log.info(f"Dump payloads addon initialized. Output dir: {self.data_dir}")

    def ensure_data_dir(self):
        """Ensure the data directory exists."""
        if not self.data_dir.exists():
            self.data_dir.mkdir(parents=True)
            ctx.log.info(f"Created data directory: {self.data_dir}")

    def response(self, flow: http.HTTPFlow) -> None:
        """Process each HTTP flow after the response is received."""
        if not flow.response:
            return

        # Extract domain from URL for organizing files
        url = flow.request.pretty_url
        domain = urlparse(url).netloc

        # Create domain directory if it doesn't exist
        domain_dir = self.data_dir / domain
        if not domain_dir.exists():
            domain_dir.mkdir(parents=True)

        # Generate timestamp for filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

        # Format data to save
        data = {
            "timestamp": timestamp,
            "url": url,
            "method": flow.request.method,
            "request": {
                "headers": dict(flow.request.headers),
                "content": flow.request.content.decode("utf-8", errors="replace")
                if flow.request.content
                else None,
            },
            "response": {
                "status_code": flow.response.status_code,
                "headers": dict(flow.response.headers),
                "content": flow.response.content.decode("utf-8", errors="replace")
                if flow.response.content
                else None,
            },
        }

        # Generate a filename based on domain, method, and timestamp
        path = flow.request.path.replace("/", "_")[:50]  # Limit path length
        if path == "":
            path = "root"

        filename = f"{flow.request.method}_{path}_{timestamp}.json"
        filepath = domain_dir / filename

        # Save to file
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        ctx.log.info(f"Dumped {flow.request.method} {url} to {filepath}")

    def _decode_content(self, content):
        """Try to decode content as JSON or text, fall back to base64 if binary."""
        if not content:
            return None

        # Try to decode as JSON first
        try:
            return json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            # Next try as plain text
            try:
                return content.decode("utf-8")
            except UnicodeDecodeError:
                # If it's binary data, return a note about the size
                return f"<binary data, {len(content)} bytes>"


# Add our addon to mitmproxy
addons = [DumpPayloads()]
