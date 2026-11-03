"""Download feed sources."""

import email.utils
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

USER_AGENT = "Mozilla/5.0"


@dataclass
class FetchResult:
    lines: list = None
    error: str = None
    last_modified: float = None  # Unix time from the Last-Modified header, if any

    @property
    def ok(self):
        return self.error is None


def download(url, timeout=60, attempts=3, backoff=2.0):
    """Fetch ``url``; HTTP errors (4xx/5xx) and network errors are retried."""
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="ignore")
                modified = response.headers.get("Last-Modified")
                stamp = None
                if modified:
                    try:
                        stamp = email.utils.parsedate_to_datetime(modified).timestamp()
                    except (TypeError, ValueError):
                        pass
                return FetchResult(lines=body.splitlines(), last_modified=stamp)
        except Exception as exc:  # network, TLS, HTTP and decode errors all count
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < attempts:
                time.sleep(backoff ** attempt)
    return FetchResult(error=last_error)


def fetch_all(feeds, workers=10, downloader=download):
    """Return ``{feed.name: FetchResult}`` for every feed."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda feed: (feed.name, downloader(feed.url)), feeds)
        return dict(results)
