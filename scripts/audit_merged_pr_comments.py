#!/usr/bin/env python3

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPOSITORY = "cypherair/cypherair"
DEFAULT_AUTHOR_REGEX = r"(codex|openai|copilot)"
GITHUB_API_URL = "https://api.github.com"


class GitHubAPIError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Audit merged PRs for PR comments, review comments, review replies, "
            "and Codex-like automated review activity."
        )
    )
    parser.add_argument(
        "--repo",
        default="",
        help="Repository as owner/name. Defaults to the git origin remote, then cypherair/cypherair.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum merged PRs to scan. 0 scans every merged PR.",
    )
    parser.add_argument(
        "--author-regex",
        default=DEFAULT_AUTHOR_REGEX,
        help=(
            "Case-insensitive regex for matching automated review authors. "
            "Use --all-authors to disable filtering. Default: %(default)s"
        ),
    )
    parser.add_argument(
        "--body-regex",
        default="",
        help="Optional case-insensitive regex that also matches comment or review body text.",
    )
    parser.add_argument(
        "--all-authors",
        action="store_true",
        help="Treat every comment and review as matching activity.",
    )
    parser.add_argument(
        "--only-with-replies",
        action="store_true",
        help="Only include PRs with inline review comment replies in the detailed output.",
    )
    parser.add_argument(
        "--include-all-prs",
        action="store_true",
        help="Include scanned PRs even when they have no replies and no matching activity.",
    )
    parser.add_argument(
        "--show-authors",
        action="store_true",
        help="Add a top-author summary for comment and review authors seen during the scan.",
    )
    parser.add_argument(
        "--full-body",
        action="store_true",
        help="Include full comment/review bodies instead of compact previews.",
    )
    parser.add_argument(
        "--preview-chars",
        type=int,
        default=220,
        help="Maximum characters per body preview when --full-body is not used.",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=4,
        help="Number of PRs to fetch concurrently. Lower this if GitHub rate-limits the scan.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Retries per GitHub API request for transient network or server failures.",
    )
    parser.add_argument(
        "--request-timeout",
        type=int,
        default=30,
        help="Seconds to wait for each GitHub API request.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the report to this path instead of stdout.",
    )
    parser.add_argument(
        "--no-gh-token",
        action="store_true",
        help="Do not fall back to `gh auth token` when GH_TOKEN/GITHUB_TOKEN are unset.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output on stderr.",
    )
    return parser.parse_args()


def infer_repository() -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(ROOT), "remote", "get-url", "origin"],
            check=True,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return DEFAULT_REPOSITORY

    remote_url = completed.stdout.strip()
    patterns = (
        r"^git@github\.com:([^/]+/[^/.]+)(?:\.git)?$",
        r"^https://github\.com/([^/]+/[^/.]+)(?:\.git)?$",
        r"^ssh://git@github\.com/([^/]+/[^/.]+)(?:\.git)?$",
    )
    for pattern in patterns:
        match = re.match(pattern, remote_url)
        if match is not None:
            return match.group(1)
    return DEFAULT_REPOSITORY


def resolve_token(use_gh_fallback: bool) -> str | None:
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        token = os.environ.get(name, "").strip()
        if token:
            return token

    if not use_gh_fallback:
        return None

    try:
        completed = subprocess.run(
            ["gh", "auth", "token"],
            check=True,
            text=True,
            capture_output=True,
            timeout=8,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None

    token = completed.stdout.strip()
    return token or None


class GitHubClient:
    def __init__(self, token: str | None, retries: int, timeout: int) -> None:
        self.token = token
        self.retries = max(0, retries)
        self.timeout = max(1, timeout)

    def request_json(
        self,
        path: str,
        params: dict[str, str | int] | None = None,
    ) -> tuple[Any, dict[str, str]]:
        url = f"{GITHUB_API_URL}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "cypherair-pr-comment-audit",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        request = urllib.request.Request(url, headers=headers)
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    payload = response.read().decode("utf-8")
                    response_headers = dict(response.headers.items())
                break
            except urllib.error.HTTPError as error:
                body = error.read().decode("utf-8", errors="replace")
                if error.code in {500, 502, 503, 504} and attempt < self.retries:
                    last_error = error
                    time.sleep(backoff_seconds(attempt))
                    continue
                raise GitHubAPIError(format_http_error(error, body)) from error
            except urllib.error.URLError as error:
                last_error = error
                if attempt < self.retries:
                    time.sleep(backoff_seconds(attempt))
                    continue
                raise GitHubAPIError(f"GitHub request failed for {url}: {error}") from error
        else:
            raise GitHubAPIError(f"GitHub request failed for {url}: {last_error}")

        if not payload:
            return None, response_headers
        return json.loads(payload), response_headers

    def paginate(
        self,
        path: str,
        params: dict[str, str | int] | None = None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        page = 1
        while True:
            page_params = dict(params or {})
            page_params["per_page"] = 100
            page_params["page"] = page
            data, headers = self.request_json(path, page_params)
            if not isinstance(data, list):
                raise GitHubAPIError(f"Expected a list response for {path}, got {type(data).__name__}")
            results.extend(data)
            if 'rel="next"' not in headers.get("Link", ""):
                return results
            page += 1


def format_http_error(error: urllib.error.HTTPError, body: str) -> str:
    message = f"GitHub API returned HTTP {error.code} for {error.url}"
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = {}

    api_message = payload.get("message") if isinstance(payload, dict) else ""
    if api_message:
        message = f"{message}: {api_message}"

    remaining = error.headers.get("X-RateLimit-Remaining", "")
    reset = error.headers.get("X-RateLimit-Reset", "")
    if remaining == "0" and reset:
        reset_at = dt.datetime.fromtimestamp(int(reset), tz=dt.timezone.utc)
        message = f"{message}. Rate limit resets at {reset_at.isoformat()}"
    return message


def backoff_seconds(attempt: int) -> float:
    return min(8.0, 0.75 * (2**attempt))


def list_merged_pull_requests(
    client: GitHubClient,
    repository: str,
    limit: int,
    quiet: bool,
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    page = 1
    while True:
        data, headers = client.request_json(
            f"/repos/{repository}/pulls",
            {
                "state": "closed",
                "sort": "created",
                "direction": "desc",
                "per_page": 100,
                "page": page,
            },
        )
        if not isinstance(data, list):
            raise GitHubAPIError("Expected a list of pull requests")

        for pull_request in data:
            if pull_request.get("merged_at"):
                merged.append(slim_pull_request(pull_request))
                if limit and len(merged) >= limit:
                    return merged

        if not quiet:
            print(f"Discovered {len(merged)} merged PRs...", file=sys.stderr)

        if not data or 'rel="next"' not in headers.get("Link", ""):
            return merged
        page += 1


def slim_pull_request(pull_request: dict[str, Any]) -> dict[str, Any]:
    return {
        "number": pull_request["number"],
        "title": pull_request.get("title", ""),
        "url": pull_request.get("html_url", ""),
        "mergedAt": pull_request.get("merged_at", ""),
        "author": user_login(pull_request.get("user")),
    }


def collect_pull_request_activity(
    client: GitHubClient,
    repository: str,
    pull_request: dict[str, Any],
    matcher: "ActivityMatcher",
    full_body: bool,
    preview_chars: int,
) -> dict[str, Any]:
    number = pull_request["number"]
    issue_comments = client.paginate(f"/repos/{repository}/issues/{number}/comments")
    reviews = client.paginate(f"/repos/{repository}/pulls/{number}/reviews")
    review_comments = client.paginate(f"/repos/{repository}/pulls/{number}/comments")

    review_comment_by_id = {
        comment.get("id"): comment
        for comment in review_comments
        if comment.get("id") is not None
    }
    reply_comments = [
        normalize_review_comment(
            comment,
            review_comment_by_id.get(comment.get("in_reply_to_id")),
            full_body,
            preview_chars,
        )
        for comment in review_comments
        if comment.get("in_reply_to_id") is not None
    ]

    matching_activity: list[dict[str, Any]] = []
    for comment in issue_comments:
        if matcher.matches(comment):
            matching_activity.append(normalize_issue_comment(comment, full_body, preview_chars))

    for review in reviews:
        if matcher.matches(review):
            matching_activity.append(normalize_review(review, full_body, preview_chars))

    for comment in review_comments:
        if matcher.matches(comment):
            matching_activity.append(
                normalize_review_comment(
                    comment,
                    review_comment_by_id.get(comment.get("in_reply_to_id")),
                    full_body,
                    preview_chars,
                )
            )

    return {
        "number": pull_request["number"],
        "title": pull_request["title"],
        "url": pull_request["url"],
        "mergedAt": pull_request["mergedAt"],
        "author": pull_request["author"],
        "issueCommentCount": len(issue_comments),
        "reviewCount": len(reviews),
        "reviewCommentCount": len(review_comments),
        "reviewReplyCount": len(reply_comments),
        "replyComments": sorted(reply_comments, key=lambda item: item.get("createdAt", "")),
        "matchingActivityCount": len(matching_activity),
        "matchingActivity": sorted(matching_activity, key=lambda item: item.get("createdAt", "")),
        "authors": count_authors(issue_comments, reviews, review_comments),
    }


class ActivityMatcher:
    def __init__(
        self,
        author_regex: str,
        body_regex: str,
        all_authors: bool,
    ) -> None:
        self.all_authors = all_authors
        self.author_pattern = compile_regex(author_regex) if author_regex else None
        self.body_pattern = compile_regex(body_regex) if body_regex else None

    def matches(self, item: dict[str, Any]) -> bool:
        if self.all_authors:
            return True

        login = user_login(item.get("user"))
        body = str(item.get("body") or "")
        if self.author_pattern is not None and self.author_pattern.search(login):
            return True
        if self.body_pattern is not None and self.body_pattern.search(body):
            return True
        return False

    def description(self) -> str:
        if self.all_authors:
            return "all authors"

        parts = []
        if self.author_pattern is not None:
            parts.append(f"author /{self.author_pattern.pattern}/i")
        if self.body_pattern is not None:
            parts.append(f"body /{self.body_pattern.pattern}/i")
        return " OR ".join(parts) if parts else "no matching filter"


def compile_regex(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern, flags=re.IGNORECASE)
    except re.error as error:
        raise GitHubAPIError(f"Invalid regex {pattern!r}: {error}") from error


def normalize_issue_comment(
    comment: dict[str, Any],
    full_body: bool,
    preview_chars: int,
) -> dict[str, Any]:
    return {
        "type": "issue_comment",
        "author": user_login(comment.get("user")),
        "createdAt": comment.get("created_at", ""),
        "url": comment.get("html_url", ""),
        "body": body_text(comment.get("body"), full_body, preview_chars),
    }


def normalize_review(
    review: dict[str, Any],
    full_body: bool,
    preview_chars: int,
) -> dict[str, Any]:
    return {
        "type": "review",
        "author": user_login(review.get("user")),
        "state": review.get("state", ""),
        "createdAt": review.get("submitted_at") or "",
        "url": review.get("html_url", ""),
        "body": body_text(review.get("body"), full_body, preview_chars),
    }


def normalize_review_comment(
    comment: dict[str, Any],
    parent: dict[str, Any] | None,
    full_body: bool,
    preview_chars: int,
) -> dict[str, Any]:
    line = comment.get("line") or comment.get("original_line") or ""
    normalized = {
        "type": "review_comment",
        "author": user_login(comment.get("user")),
        "createdAt": comment.get("created_at", ""),
        "url": comment.get("html_url", ""),
        "path": comment.get("path", ""),
        "line": line,
        "inReplyToId": comment.get("in_reply_to_id"),
        "body": body_text(comment.get("body"), full_body, preview_chars),
    }
    if parent is not None:
        normalized["replyTo"] = {
            "author": user_login(parent.get("user")),
            "url": parent.get("html_url", ""),
            "body": body_text(parent.get("body"), full_body, preview_chars),
        }
    return normalized


def count_authors(
    issue_comments: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    review_comments: list[dict[str, Any]],
) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in [*issue_comments, *reviews, *review_comments]:
        login = user_login(item.get("user"))
        if login:
            counter[login] += 1
    return dict(counter)


def user_login(user: Any) -> str:
    if isinstance(user, dict):
        login = user.get("login")
        return str(login) if login is not None else ""
    return ""


def body_text(body: Any, full_body: bool, preview_chars: int) -> str:
    text = str(body or "").strip()
    if full_body:
        return text

    text = re.sub(r"!\[[^\]]*\]\([^)]+\)", "", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\s+", " ", text)
    if len(text) <= preview_chars:
        return text
    return f"{text[: max(0, preview_chars - 1)].rstrip()}..."


def build_report(
    repository: str,
    matcher: ActivityMatcher,
    pull_request_reports: list[dict[str, Any]],
    args: argparse.Namespace,
) -> dict[str, Any]:
    reports = sorted(
        pull_request_reports,
        key=lambda item: item["number"],
        reverse=True,
    )
    if args.only_with_replies:
        included = [item for item in reports if item["reviewReplyCount"] > 0]
    elif args.include_all_prs:
        included = reports
    else:
        included = [
            item
            for item in reports
            if item["reviewReplyCount"] > 0 or item["matchingActivityCount"] > 0
        ]

    aggregate_authors: Counter[str] = Counter()
    for report in reports:
        aggregate_authors.update(report["authors"])

    return {
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repository": repository,
        "matchingFilter": matcher.description(),
        "scannedMergedPullRequests": len(reports),
        "pullRequestsWithReviewReplies": sum(
            1 for item in reports if item["reviewReplyCount"] > 0
        ),
        "pullRequestsWithMatchingActivity": sum(
            1 for item in reports if item["matchingActivityCount"] > 0
        ),
        "totalReviewReplies": sum(item["reviewReplyCount"] for item in reports),
        "totalMatchingActivity": sum(item["matchingActivityCount"] for item in reports),
        "topAuthors": aggregate_authors.most_common(25),
        "pullRequests": included,
    }


def format_markdown(report: dict[str, Any], show_authors: bool) -> str:
    lines = [
        "# Merged PR Comment Audit",
        "",
        f"- Repository: `{report['repository']}`",
        f"- Generated: `{report['generatedAt']}`",
        f"- Matching filter: `{report['matchingFilter']}`",
        f"- Merged PRs scanned: `{report['scannedMergedPullRequests']}`",
        f"- PRs with inline review replies: `{report['pullRequestsWithReviewReplies']}`",
        f"- Total inline review replies: `{report['totalReviewReplies']}`",
        f"- PRs with matching review/comment activity: `{report['pullRequestsWithMatchingActivity']}`",
        f"- Total matching review/comment items: `{report['totalMatchingActivity']}`",
        "",
        (
            "Inline review replies are GitHub pull request review comments with "
            "`in_reply_to_id`; top-level PR conversation comments are counted separately."
        ),
        "",
    ]

    if show_authors:
        lines.append("## Top Comment And Review Authors")
        lines.append("")
        if report["topAuthors"]:
            for login, count in report["topAuthors"]:
                lines.append(f"- `{login}`: {count}")
        else:
            lines.append("- No comment or review authors found.")
        lines.append("")

    pull_requests = report["pullRequests"]
    if not pull_requests:
        lines.extend(
            [
                "## Matching Pull Requests",
                "",
                "No merged PRs matched the selected output filters.",
                "",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    lines.extend(["## Pull Requests With Replies Or Matching Activity", ""])
    for item in pull_requests:
        lines.extend(format_pull_request_markdown(item))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_pull_request_markdown(item: dict[str, Any]) -> list[str]:
    heading = f"### [#{item['number']} {item['title']}]({item['url']})"
    lines = [
        heading,
        "",
        f"- Merged: `{item['mergedAt']}` by `{item['author']}`",
        f"- Conversation comments: `{item['issueCommentCount']}`",
        f"- Reviews: `{item['reviewCount']}`",
        f"- Inline review comments: `{item['reviewCommentCount']}`",
        f"- Inline review replies: `{item['reviewReplyCount']}`",
        f"- Matching review/comment items: `{item['matchingActivityCount']}`",
    ]

    if item["replyComments"]:
        lines.extend(["", "Review replies:"])
        for comment in item["replyComments"]:
            lines.append(f"- {format_activity_item(comment)}")

    if item["matchingActivity"]:
        lines.extend(["", "Matching activity:"])
        for activity in item["matchingActivity"]:
            lines.append(f"- {format_activity_item(activity)}")
    return lines


def format_activity_item(activity: dict[str, Any]) -> str:
    kind = activity["type"]
    author = activity.get("author", "")
    created_at = activity.get("createdAt", "")
    body = activity.get("body", "")
    url = activity.get("url", "")

    details = ""
    if kind == "review":
        state = activity.get("state", "")
        details = f" review `{state}`" if state else " review"
    elif kind == "review_comment":
        location = activity.get("path", "")
        line = activity.get("line", "")
        if location and line:
            details = f" inline comment on `{location}:{line}`"
        elif location:
            details = f" inline comment on `{location}`"
        else:
            details = " inline comment"

        reply_to = activity.get("replyTo")
        if isinstance(reply_to, dict) and reply_to.get("author"):
            details = f"{details}, replying to `{reply_to['author']}`"
    else:
        details = " conversation comment"

    prefix = f"`{author}`{details} at `{created_at}`"
    if url:
        prefix = f"{prefix}: {body} ([comment]({url}))"
    else:
        prefix = f"{prefix}: {body}"
    return wrap_markdown_list_item(prefix)


def wrap_markdown_list_item(text: str) -> str:
    return text


def write_output(path: Path | None, text: str) -> None:
    if path is None:
        print(text, end="")
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    args = parse_args()
    repository = args.repo.strip() or infer_repository()
    token = resolve_token(use_gh_fallback=not args.no_gh_token)
    if token is None and not args.quiet:
        print(
            "No GH_TOKEN/GITHUB_TOKEN or `gh auth token` was available. "
            "Unauthenticated GitHub API scans have a low rate limit.",
            file=sys.stderr,
        )

    matcher = ActivityMatcher(
        author_regex=args.author_regex,
        body_regex=args.body_regex,
        all_authors=args.all_authors,
    )
    client = GitHubClient(token, retries=args.retries, timeout=args.request_timeout)

    try:
        pull_requests = list_merged_pull_requests(
            client,
            repository,
            limit=args.limit,
            quiet=args.quiet,
        )
        if not args.quiet:
            print(f"Scanning activity for {len(pull_requests)} merged PRs...", file=sys.stderr)

        reports: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as executor:
            futures = [
                executor.submit(
                    collect_pull_request_activity,
                    client,
                    repository,
                    pull_request,
                    matcher,
                    args.full_body,
                    args.preview_chars,
                )
                for pull_request in pull_requests
            ]
            for index, future in enumerate(concurrent.futures.as_completed(futures), start=1):
                reports.append(future.result())
                if not args.quiet and (index == len(futures) or index % 25 == 0):
                    print(f"Scanned {index}/{len(futures)} PRs...", file=sys.stderr)

        report = build_report(repository, matcher, reports, args)
    except GitHubAPIError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130

    if args.format == "json":
        output = json.dumps(report, indent=2) + "\n"
    else:
        output = format_markdown(report, args.show_authors)
    write_output(args.output, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
