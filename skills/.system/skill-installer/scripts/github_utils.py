#!/usr/bin/env python3
"""Shared GitHub helpers for skill install scripts."""

from __future__ import annotations

import os
import urllib.parse
import urllib.request

ALLOWED_GITHUB_HOSTS = {"api.github.com", "codeload.github.com"}


def github_request(url: str, user_agent: str) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_GITHUB_HOSTS:
        raise ValueError("Only HTTPS GitHub API and codeload URLs are allowed.")
    headers = {"User-Agent": user_agent}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read()


def github_api_contents_url(repo: str, path: str, ref: str) -> str:
    return f"https://api.github.com/repos/{repo}/contents/{path}?ref={ref}"
