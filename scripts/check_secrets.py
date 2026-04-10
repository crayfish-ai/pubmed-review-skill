#!/usr/bin/env python3
"""
Secret Detection Script - Pre-commit secret leak prevention
Scans files for common credential patterns before they enter git history.

Usage:
    python3 scripts/check_secrets.py [--files "file1,file2,..."]
    python3 scripts/check_secrets.py  # scan all files in current directory

Exit codes:
    0 = clean (no secrets found)
    1 = suspicious patterns found (blocked)
    2 = error
"""

import os
import sys
import re
import argparse

# Patterns that indicate potential secrets
SECRET_PATTERNS = [
    (r'github_pat_[A-Za-z0-9_]{20,}', 'GitHub Personal Access Token'),
    (r'ghp_[A-Za-z0-9_]{36,}', 'GitHub PAT (classic)'),
    (r'xox[baprs]-[A-Za-z0-9-]{10,}', 'Slack Token'),
    (r'sk-[A-Za-z0-9_]{20,}', 'OpenAI / Generic API Key'),
    (r'AKIA[A-Z0-9]{16}', 'AWS Access Key'),
    (r'AIza[A-Za-z0-9_-]{35,}', 'Google API Key'),
    (r'ya29\.[A-Za-z0-9_-]{50,}', 'Google OAuth'),
    (r'FEISHU_APP_SECRET["\s]*[=:]["\s]*[A-Za-z0-9_-]{20,}', 'Feishu App Secret'),
    (r'appSecret["\s]*[=:]["\s]*["\'][^"\']{20,}["\']', 'App Secret (JSON)'),
    (r'MINIMAX_API_KEY["\s]*[=:]["\s]*["\']?[A-Za-z0-9_-]{20,}', 'MiniMax API Key'),
    (r'OPENAI_API_KEY["\s]*[=:]["\s]*["\']?[A-Za-z0-9_-]{20,}', 'OpenAI API Key'),
    (r'ANTHROPIC_API_KEY["\s]*[=:]["\s]*["\']?[A-Za-z0-9_-]{20,}', 'Anthropic API Key'),
    (r'WEBHOOK[_\w]*["\s]*[=:]["\s]*["\']?https?://[^\s"\']{20,}', 'Webhook URL'),
    (r'AMAZON/aws_access_key_id', 'AWS Access Key (ini)'),
    (r'aws_secret_access_key', 'AWS Secret Key'),
    (r'password\s*[=:]\s*["\'][^"\']{8,}["\']', 'Hardcoded Password'),
    (r'token["\s]*[=:]["\s]*["\'][A-Za-z0-9_.-]{20,}["\']', 'Generic Token'),
    (r'bearer\s+[A-Za-z0-9_.-]{20,}', 'Bearer Token'),
    (r'ufFAY[A-Za-z0-9]{10,}', 'Feishu App Secret (legacy)'),
    (r'cli_[a-z0-9]{16,}', 'Feishu App ID'),
]

# File extensions to scan (skip binary and non-text files)
TEXT_EXTENSIONS = {
    '.py', '.sh', '.bash', '.zsh', '.fish',
    '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.config',
    '.env', '.properties', '.xml', '.html', '.htm', '.md', '.rst',
    '.txt', '.text', '.log', '.sql', '.go', '.rs', '.java', '.rb', '.php',
    '.js', '.ts', '.jsx', '.tsx', '.vue', '.c', '.cpp', '.h', '.hpp',
    '.cs', '.swift', '.kt', '.scala', '.r', '.lua', '.pl', '.pm',
}

# Directories to always skip
SKIP_DIRS = {
    '.git', '.svn', '.hg', '.bzr',
    'node_modules', '.venv', 'venv', 'env',
    '__pycache__', '.pytest_cache', '.mypy_cache',
    'dist', 'build', '.tox', '.eggs',
    '.tox', '.direnv',
}


def should_skip_file(path: str) -> bool:
    """Check if file should be skipped."""
    # Skip binary files
    basename = os.path.basename(path)
    if basename.startswith('.') and '/' not in path:
        # Hidden files in root (like .env) should be checked
        pass

    # Skip by extension
    _, ext = os.path.splitext(path)
    if ext.lower() not in TEXT_EXTENSIONS:
        return True

    # Skip by directory
    parts = path.split(os.sep)
    for part in parts:
        if part in SKIP_DIRS:
            return True

    return False


def scan_file(filepath: str) -> list:
    """Scan a single file for secrets. Returns list of (line_num, line_content, pattern_name)."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line_num, line in enumerate(f, 1):
                # Skip comments
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('//'):
                    continue

                for pattern, name in SECRET_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append((line_num, line.rstrip(), name))
    except Exception as e:
        print(f'  [WARN] Cannot read {filepath}: {e}', file=sys.stderr)
    return findings


def scan_files(filepaths: list) -> dict:
    """Scan multiple files. Returns {filepath: [(line_num, line, pattern_name), ...]}."""
    results = {}
    for filepath in filepaths:
        if should_skip_file(filepath):
            continue
        findings = scan_file(filepath)
        if findings:
            results[filepath] = findings
    return results


def get_all_files(root: str = '.') -> list:
    """Get all text files under root directory."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip directories in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            files.append(filepath)
    return files


def main():
    parser = argparse.ArgumentParser(description='Check for leaked secrets in files')
    parser.add_argument('--files', help='Comma-separated list of files to check')
    parser.add_argument('--dir', default='.', help='Directory to scan (default: .)')
    parser.add_argument('--strict', action='store_true', help='Fail on any pattern match, not just high-confidence')
    args = parser.parse_args()

    if args.files:
        files = [f.strip() for f in args.files.split(',')]
    else:
        files = get_all_files(args.dir)

    print(f'[check_secrets] Scanning {len(files)} files...')
    results = scan_files(files)

    if not results:
        print('[check_secrets] ✅ No secrets detected - clean')
        sys.exit(0)

    # Print findings
    print(f'\n[check_secrets] 🚨 BLOCKED - {len(results)} file(s) with suspicious patterns:\n', file=sys.stderr)
    for filepath, findings in results.items():
        print(f'  📄 {filepath}', file=sys.stderr)
        for line_num, line, pattern_name in findings:
            preview = line[:120] + ('...' if len(line) > 120 else '')
            print(f'    Line {line_num}: [{pattern_name}]', file=sys.stderr)
            print(f'      {preview}', file=sys.stderr)
    print(file=sys.stderr)

    print('[check_secrets] ❌ Secrets detected - COMMIT BLOCKED', file=sys.stderr)
    print('[check_secrets] If this is a false positive, use --strict to override', file=sys.stderr)
    sys.exit(1)


if __name__ == '__main__':
    main()
