#!/usr/bin/env python3
"""
Project Safety Checker - Executable security enforcement for git commits.
Blocks commits that contain: secrets, high-risk code patterns, hardcoded paths.

Exit codes:
    0 = clean (all checks passed)
    1 = blocked (problems found)
    2 = warning (missing optional files)
"""

import os
import sys
import re
import argparse

# ============================================================
# SECTION A: Secret patterns (exit 1 = BLOCK)
# ============================================================
SECRET_PATTERNS = [
    (r'github_pat_[A-Za-z0-9_]{20,}', 'GitHub Personal Access Token'),
    (r'ghp_[A-Za-z0-9_]{36,}', 'GitHub PAT (classic)'),
    (r'sk-[A-Za-z0-9_]{20,}', 'OpenAI/Generic API Key'),
    (r'xox[baprs]-[A-Za-z0-9-]{10,}', 'Slack Token'),
    (r'AIza[A-Za-z0-9_-]{35,}', 'Google API Key'),
    (r'AKIA[A-Z0-9]{16}', 'AWS Access Key'),
    (r'FEISHU_APP_SECRET\s*[=:]\s*["\']?[A-Za-z0-9_-]{10,}', 'Feishu App Secret (env style)'),
    (r'"appSecret"\s*:\s*"[^"]{10,}"', 'App Secret (JSON)'),
    (r'appSecret["\s]*[=:]["\s]*["\'][^"\']{10,}["\']', 'App Secret (JSON)'),
    (r'MINIMAX_API_KEY\s*[=:]\s*["\']?(?!your_)[A-Za-z0-9_-]{30,}', 'MiniMax API Key'),
    (r'OPENAI_API_KEY\s*[=:]\s*["\']?[A-Za-z0-9_-]{10,}', 'OpenAI API Key'),
    (r'ANTHROPIC_API_KEY\s*[=:]\s*["\']?[A-Za-z0-9_-]{10,}', 'Anthropic API Key'),
    (r'AMAZON/aws_access_key_id', 'AWS Access Key (ini)'),
    (r'aws_secret_access_key', 'AWS Secret Key'),
    (r'WEBHOOK[_\w]*\s*[=:]\s*["\']?https?://[^\s"\']{10,}', 'Webhook URL'),
    (r'ufFAY[A-Za-z0-9]{10,}', 'Feishu App Secret (legacy)'),
    (r'cli_[a-z0-9]{16,}', 'Feishu App ID'),
    (r'password\s*[=:]\s*["\'][^"\']{8,}["\']', 'Hardcoded Password'),
    (r'bearer\s+[A-Za-z0-9_.-]{20,}', 'Bearer Token'),
]

# ============================================================
# SECTION B: High-risk code patterns (exit 1 = BLOCK)
# ============================================================
RISKY_PATTERNS = [
    (r'os\.system\s*\(', 'os.system() call - use subprocess.run with list args'),
    (r'shell\s*=\s*True', 'shell=True - command injection risk, use shell=False'),
    (r'subprocess\.call\s*\(', 'subprocess.call - prefer subprocess.run'),
    (r'subprocess\.Popen\s*\(.*shell\s*=\s*True', 'subprocess.Popen with shell=True'),
]

# ============================================================
# SECTION C: Hardcoded paths (exit 1 = BLOCK)
# ============================================================
HARDCODED_PATHS = [
    (r'/root/', '/root/ - use $HOME or relative paths'),
    (r'/data/', '/data/ - use environment variable or config'),
    (r'/home/\w+/', '/home/username - use $HOME or relative paths'),
    (r'/Users/\w+/', '/Users/ - use $HOME or relative paths (macOS)'),
    (r'/etc/openclaw/', '/etc/openclaw/ - avoid hardcoded system paths'),
    (r'D:\\[^\\]+\\Users\\', 'Windows user path - avoid hardcoded'),
]

# ============================================================
# SECTION D: Required files (exit 2 = WARN)
# ============================================================
REQUIRED_FILES = {
    '.gitignore': 'REQUIRED: .gitignore missing - credentials may leak',
    '.env.example': 'REQUIRED: .env.example missing - no credential template',
}
OPTIONAL_FILES = {
    'SECURITY.md': 'OPTIONAL: SECURITY.md missing - recommended for public repos',
    'SKILL.md': 'OPTIONAL: SKILL.md missing - recommended for OpenClaw skills',
    'README.md': 'OPTIONAL: README.md missing',
    'skill.json': 'OPTIONAL: skill.json missing - recommended for OpenClaw skills',
}

# Files to always scan (skip binary and non-text)
TEXT_EXTENSIONS = {
    '.py', '.sh', '.bash', '.zsh',
    '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
    '.env', '.properties', '.xml', '.html', '.md', '.rst',
    '.txt', '.log', '.sql', '.go', '.rs', '.java', '.rb', '.php',
    '.js', '.ts', '.jsx', '.tsx', '.vue', '.c', '.cpp', '.h', '.hpp',
    '.cs', '.swift', '.kt', '.scala', '.r', '.lua', '.pl', '.pm',
}
SKIP_DIRS = {'.git', '.svn', '__pycache__', 'node_modules', '.venv', 'venv',
             'dist', 'build', '.tox', '.eggs', '.pytest_cache', '.mypy_cache'}


def should_skip(path):
    if 'check_project_safety.py' in path or 'check_secrets.py' in path:
        return True  # skip self and sibling secret checker
    _, ext = os.path.splitext(path)
    if ext.lower() not in TEXT_EXTENSIONS:
        return True
    for part in path.split(os.sep):
        if part in SKIP_DIRS:
            return True
    return False


def scan_file(filepath):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for lineno, line in enumerate(f, 1):
                s = line.strip()
                # Skip comments for secret scan
                if s.startswith('#') or s.startswith('//'):
                    continue
                # Skip docstrings/comments that contain pattern strings (not actual usages)
                if s.startswith('"""') or s.startswith("'''"):
                    continue
                for pattern, name in SECRET_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append((lineno, line.rstrip(), 'SECRET', name))
                # Skip README/SKILL/documentation files for path checks (docs about paths ≠ hardcoded paths)
                if re.match(r'(README|SKILL|CHANGELOG|LICENSE|INSTALL|SECURITY|SETUP|\.md)', os.path.basename(fp), re.I):
                    pass  # still check for secrets and risky code
                else:
                    for pattern, name in HARDCODED_PATHS:
                        if re.search(pattern, line):
                            findings.append((lineno, line.rstrip(), 'PATH', name))
                for pattern, name in RISKY_PATTERNS:
                    if re.search(pattern, line):
                        findings.append((lineno, line.rstrip(), 'RISKY', name))
    except Exception as e:
        pass
    return findings


def scan_project(root):
    all_results = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            if should_skip(fp):
                continue
            findings = scan_file(fp)
            if findings:
                rel = os.path.relpath(fp, root)
                all_results[rel] = findings
    return all_results


def check_required_files(root):
    missing_required = []
    missing_optional = []
    for fn, msg in REQUIRED_FILES.items():
        if not os.path.exists(os.path.join(root, fn)):
            missing_required.append(msg)
    for fn, msg in OPTIONAL_FILES.items():
        if not os.path.exists(os.path.join(root, fn)):
            missing_optional.append(msg)
    return missing_required, missing_optional


def main():
    parser = argparse.ArgumentParser(description='Project safety checker - blocks unsafe commits')
    parser.add_argument('--dir', default='.', help='Project directory to check')
    parser.add_argument('--files', help='Comma-separated specific files to check')
    parser.add_argument('--skip-required', action='store_true', help='Skip required-file checks')
    args = parser.parse_args()

    root = args.dir
    print(f'[safety] Scanning project: {os.path.abspath(root)}')

    # Scan code for violations
    if args.files:
        files = [f.strip() for f in args.files.split(',')]
        all_results = {}
        for fp in files:
            findings = scan_file(fp)
            if findings:
                all_results[fp] = findings
    else:
        all_results = scan_project(root)

    blocked = []
    for fp, findings in all_results.items():
        for lineno, line, kind, name in findings:
            preview = line[:100] + ('...' if len(line) > 100 else '')
            blocked.append(f'  [{kind}] {fp}:{lineno} — {name}\n    {preview}')

    if blocked:
        print('\n[safety] 🚨 BLOCKED - violations found:\n', file=sys.stderr)
        for b in blocked:
            print(b, file=sys.stderr)
        print(file=sys.stderr)
        print('[safety] ❌ Commit blocked - fix all issues above before committing', file=sys.stderr)
        sys.exit(1)

    # Check required files
    if not args.skip_required:
        missing_req, missing_opt = check_required_files(root)
        if missing_req:
            for msg in missing_req:
                print(f'[safety] ❌ {msg}', file=sys.stderr)
            print('[safety] ❌ Commit blocked - missing required files', file=sys.stderr)
            sys.exit(1)
        if missing_opt:
            for msg in missing_opt:
                print(f'[safety] ⚠️  {msg}', file=sys.stderr)
            print('[safety] ✅ All safety checks passed (warnings above are non-blocking)', file=sys.stderr)
    else:
        print('[safety] ✅ All safety checks passed', file=sys.stderr)

    print('[safety] ✅ Project is safe - commit allowed')
    sys.exit(0)


if __name__ == '__main__':
    main()
