"""Explicit host/path-bound saved session headers for passive HTTPS review."""

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from .models import ValidationError
from .providers import ProviderError
from .report_io import read_regular
from .scan_bundle import document
from .site_review import canonical_url

NOTICE = (
    "Operator-supplied static session headers were scoped to this exact HTTPS host/path. "
    "Identity, login success and session permissions are unverified. No login automation, "
    "cookie refresh, redirects, JavaScript, forms or application-logic tests occurred. "
    "Page targets are indexed aliases; URLs belong only in a separate private path map. "
    "A GET can still have effects; use an approved test account and target."
)
FAILURES = {
    "expired": "Saved session expired before this request; no request sent.",
    "scope": "Saved-session request was outside its approved host/path; no request sent.",
    "denied": "Target rejected session access with HTTP 401/403; further requests stopped.",
}


class ScopedSession:
    def __init__(self, client, *, host, path_prefix, headers, expires_at, clock=None):
        self.client, self.host, self.prefix = client, host, path_prefix
        self._headers = dict(headers)
        self.expires_at = expires_at
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.blocked = False
        self.failure_code = None

    @classmethod
    def from_file(cls, path, client, *, target, path_prefix, clock=None):
        current = (clock or (lambda: datetime.now(timezone.utc)))()
        value = document(read_regular(path, 16 * 1024))
        if set(value) != {"schema_version", "host", "path_prefix", "expires_at", "headers"} or (
            type(value["schema_version"]) is not int or value["schema_version"] != 1
        ):
            raise ValidationError("Invalid saved-session configuration")
        url = canonical_url(target)
        host = urlsplit(url).hostname
        if not isinstance(path_prefix, str) or not path_prefix.startswith("/"):
            raise ValidationError("Saved session requires an absolute directory path")
        if value["host"] != host or value["path_prefix"] != path_prefix:
            raise ValidationError("Saved session must match the exact approved host and path")
        scope = canonical_url(f"https://{host}{path_prefix}")
        if (urlsplit(scope).path != path_prefix or not path_prefix.endswith("/")
                or not urlsplit(url).path.startswith(path_prefix)):
            raise ValidationError("Saved session requires a matching absolute directory path")
        try:
            expires = datetime.fromisoformat(value["expires_at"])
            if (expires.tzinfo is None or expires.utcoffset() != timedelta(0)
                    or not current < expires <= current + timedelta(hours=24)):
                raise ValueError
        except (ValueError, TypeError, OverflowError):
            raise ValidationError("Saved session expiry must be UTC and within 24 hours") from None
        headers = value["headers"]
        if (not isinstance(headers, dict) or not headers
                or not set(headers) <= {"Authorization", "Cookie"}):
            raise ValidationError("Saved session accepts only Authorization and Cookie headers")
        if any(not isinstance(item, str) or not 1 <= len(item) <= 8192 or not item.isascii()
               or re.search(r"[\x00-\x1f\x7f]", item)
               for item in headers.values()):
            raise ValidationError("Saved-session header values are invalid; values omitted")
        if any(not item.strip() for item in headers.values()):
            raise ValidationError("Saved-session headers must not be blank")
        return cls(client, host=host, path_prefix=path_prefix, headers=headers,
                   expires_at=expires, clock=clock)

    def request(self, target):
        url = canonical_url(target)
        if self.blocked:
            self.failure_code = "denied"
        elif self.clock() >= self.expires_at:
            self.failure_code = "expired"
        elif (urlsplit(url).hostname != self.host
                or not urlsplit(url).path.startswith(self.prefix)):
            self.failure_code = "scope"
        else:
            self.failure_code = None
        if self.failure_code is not None:
            raise ProviderError("Saved session is expired, stopped or outside its scope")
        response = self.client.request(url, headers=dict(self._headers))
        if response.status in (401, 403):
            self.blocked = True
            self.failure_code = "denied"
            raise ProviderError("Target rejected session access; further session requests stopped")
        return response
