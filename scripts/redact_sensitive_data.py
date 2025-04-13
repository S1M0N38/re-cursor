#!/usr/bin/env python3
"""
Redact sensitive information from JSON files.
This script scans JSON files and creates redacted copies by targeting specific keys
that contain sensitive information, preserving the original files.
"""

import json
import os
import re
import sys
import shutil
from pathlib import Path

# Keys that contain sensitive data to be redacted
SENSITIVE_KEYS = {
    # Authentication and authorization
    "authorization": "Bearer xxx-AUTH-TOKEN-xxx",
    "x-client-key": "xxx-CLIENT-KEY-xxx",
    "x-cursor-checksum": "xxx-CHECKSUM-xxx",
    "x-cursor-config-version": "xxx-CONFIG-VERSION-xxx",
    # Request and trace identifiers
    "traceparent": "xxx-TRACE-ID-xxx",
    "x-request-id": "xxx-REQUEST-ID-xxx",
    "x-amzn-trace-id": "xxx-TRACE-ID-xxx",
    # Session identifiers
    "x-session-id": "xxx-SESSION-ID-xxx",
    # Other potential sensitive headers
    "x-api-key": "xxx-API-KEY-xxx",
    "cookie": "xxx-COOKIE-xxx",
}

# For string values that should be redacted based on patterns
# These are applied to values when the key doesn't match SENSITIVE_KEYS
SENSITIVE_PATTERNS = [
    # JWT tokens
    (
        r"eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.?[a-zA-Z0-9_-]{5,}?",
        "xxx-JWT-TOKEN-xxx",
    ),
    # UUIDs and similar identifiers
    (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "xxx-UUID-xxx"),
    # Hexadecimal strings that might be tokens (longer than 16 characters)
    (r"\b[0-9a-f]{16,}\b", "xxx-HEX-xxx"),
]


def redact_sensitive_data(content):
    """Process content to replace sensitive data."""
    if not content:
        return content

    # If it's a string that might be JSON, try to parse it
    if isinstance(content, str):
        try:
            # Try to parse as JSON
            data = json.loads(content)
            return redact_dict_or_list(data)
        except json.JSONDecodeError:
            # If it's not JSON, apply pattern-based redaction
            return redact_string(content)

    # If it's already a dictionary or list, process it
    if isinstance(content, (dict, list)):
        return redact_dict_or_list(content)

    # For any other type, return as is
    return content


def redact_string(text):
    """Apply pattern-based redaction to a string."""
    if not isinstance(text, str):
        return text

    for pattern, replacement in SENSITIVE_PATTERNS:
        text = re.sub(pattern, replacement, text)

    return text


def redact_dict_or_list(data):
    """Recursively redact sensitive data in dictionaries and lists."""
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            key_lower = key.lower() if isinstance(key, str) else key

            # Check if this is a sensitive key
            if key_lower in SENSITIVE_KEYS:
                result[key] = SENSITIVE_KEYS[key_lower]
            elif isinstance(value, (dict, list)):
                # Recursively process nested structures
                result[key] = redact_dict_or_list(value)
            elif isinstance(value, str):
                # Apply pattern-based redaction to strings
                result[key] = redact_string(value)
            else:
                # Keep non-string values as is
                result[key] = value

        return result

    elif isinstance(data, list):
        return [redact_dict_or_list(item) for item in data]

    else:
        return data


def create_redacted_copy(source_path, target_path):
    """Create a redacted copy of a JSON file using key-based redaction."""
    try:
        with open(source_path, "r", encoding="utf-8") as f:
            try:
                # Try to parse as JSON
                data = json.load(f)

                # Apply the redaction process to the entire data structure
                redacted_data = redact_dict_or_list(data)

                # Write redacted data to the target path
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "w", encoding="utf-8") as f_out:
                    json.dump(redacted_data, f_out, indent=2)
                print(f"Created redacted copy: {target_path}")
                return True

            except json.JSONDecodeError:
                # If not valid JSON, process as text
                with open(source_path, "r", encoding="utf-8") as f_text:
                    content = f_text.read()
                    redacted_content = redact_string(content)

                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "w", encoding="utf-8") as f_out:
                    f_out.write(redacted_content)
                print(f"Created redacted copy as text: {target_path}")
                return True

    except Exception as e:
        print(f"Error processing {source_path}: {e}")
        return False


def main():
    """Find and process all JSON files in the specified directory."""
    if len(sys.argv) != 2:
        print("Usage: python redact_sensitive_data.py <directory>")
        sys.exit(1)

    source_directory = sys.argv[1]
    source_dir = Path(source_directory)

    if not source_dir.exists() or not source_dir.is_dir():
        print(f"Error: {source_directory} is not a valid directory")
        sys.exit(1)

    # Create a new directory for redacted files
    redacted_dir_name = f"{source_dir.name}_redacted"
    redacted_dir = source_dir.parent / redacted_dir_name

    # If the redacted directory already exists, ask for confirmation to overwrite
    if redacted_dir.exists():
        response = input(
            f"The directory {redacted_dir} already exists. Do you want to overwrite it? (y/n): "
        )
        if response.lower() != "y":
            print("Operation cancelled.")
            sys.exit(0)
        shutil.rmtree(redacted_dir)

    # Create the redacted directory
    redacted_dir.mkdir(exist_ok=True)
    print(f"Created directory for redacted copies: {redacted_dir}")

    processed_count = 0
    error_count = 0

    # Process all JSON files in the directory and its subdirectories
    for source_file_path in source_dir.glob("**/*.json"):
        # Create corresponding path in the redacted directory
        relative_path = source_file_path.relative_to(source_dir)
        target_file_path = redacted_dir / relative_path

        if create_redacted_copy(source_file_path, target_file_path):
            processed_count += 1
        else:
            error_count += 1

    print(f"\nSummary:")
    print(f"Files processed: {processed_count}")
    print(f"Errors: {error_count}")
    print(f"Redacted copies saved to: {redacted_dir}")


if __name__ == "__main__":
    main()
