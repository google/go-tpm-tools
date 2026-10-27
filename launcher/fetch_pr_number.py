#!/usr/bin/env python3
"""Helper script to fetch the open GitHub PR number matching a commit SHA."""

import argparse
import json
import ssl
import sys
import urllib.request


_URL = "https://api.github.com/repos/google/go-tpm-tools/pulls?state=open"


def main():
  parser = argparse.ArgumentParser(
      description="Fetch GitHub PR number for a commit SHA."
  )
  parser.add_argument("commit_sha", help="Commit SHA (at least 7 characters)")
  parser.add_argument(
      "--no-ssl-verify",
      action="store_true",
      help=(
          "Disable SSL certificate verification (useful when running on"
          " unconfigured macOS or proxy environments)"
      ),
  )
  args = parser.parse_args()

  if len(args.commit_sha) < 7:
    print("Error: commit_sha must be at least 7 characters", file=sys.stderr)
    sys.exit(1)

  req = urllib.request.Request(_URL, headers={"User-Agent": "CloudBuild"})

  ctx = None
  if args.no_ssl_verify:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

  try:
    with urllib.request.urlopen(req, context=ctx) as resp:
      prs = json.loads(resp.read().decode())
  except Exception as e:
    print(
        f"Error fetching PRs from GitHub API: {e}. (Consider using"
        " --no-ssl-verify if running locally or behind a proxy)",
        file=sys.stderr,
    )
    sys.exit(1)

  matches = []
  for pr in prs:
    head_sha = pr.get("head", {}).get("sha", "")
    if head_sha and head_sha.startswith(args.commit_sha):
      matches.append(pr)

  if len(matches) > 1:
    print(
        f"Error: Multiple open PRs matched prefix '{args.commit_sha}'. Please"
        " use a full SHA.",
        file=sys.stderr,
    )
    sys.exit(1)

  if matches:
    print(matches[0].get("number"))


if __name__ == "__main__":
  main()
