"""Bounded HTTPS with exact host scope, pinned public DNS addresses and no redirects."""

import http.client
import ipaddress
import json
import re
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from ._version import __version__
from .models import ValidationError
from .providers import ProviderError


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    header_items: tuple[tuple[str, str], ...] = ()
    body_status: str = "complete"

    def document(self) -> dict:
        if self.body_status != "complete":
            raise ProviderError("Provider response body is incomplete")
        try:
            result = json.loads(self.body)
            if not isinstance(result, dict):
                raise ValueError
            # Bound structure independently of interpreter-specific JSON recursion limits.
            # Keep iterator frames rather than duplicating a broad response into a worklist.
            stack = [(iter(result.values()), 1)]
            while stack:
                children, depth = stack[-1]
                try:
                    value = next(children)
                except StopIteration:
                    stack.pop()
                    continue
                if isinstance(value, (dict, list)):
                    if depth >= 64:
                        raise ValueError
                    nested = value.values() if isinstance(value, dict) else value
                    stack.append((iter(nested), depth + 1))
            return result
        except (ValueError, UnicodeError, RecursionError):
            raise ProviderError("Provider returned invalid JSON") from None


def public_address(host: str) -> str:
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        ips = [str(item[4][0]) for item in addresses]
        if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
            raise ValueError
        return ips[0]
    except (OSError, ValueError):
        raise ProviderError(
            "Target DNS is unavailable or resolves outside public address space"
        ) from None


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, timeout: float):
        super().__init__(host, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        # The TLS name remains the original host; the connection uses the validated IP.
        raw = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class PublicHTTPS:
    def __init__(
        self, allowed_hosts, *, max_bytes=1024 * 1024, max_requests=110, timeout=15,
        allow_partial_body=False,
    ):
        if (
            type(max_bytes) is not int or not 1 <= max_bytes <= 8 * 1024 * 1024
            or type(max_requests) is not int or not 1 <= max_requests <= 200
        ):
            raise ValidationError("Invalid HTTP size or request limit")
        if type(timeout) not in (int, float) or not 0 < timeout <= 60:
            raise ValidationError("HTTP timeout must be between 0 and 60 seconds")
        if type(allow_partial_body) is not bool:
            raise ValidationError("Partial response selection must be boolean")
        self.allow_partial_body = allow_partial_body
        self.allowed_hosts = frozenset(h.lower() for h in allowed_hosts)
        self.max_bytes, self.max_requests, self.timeout = max_bytes, max_requests, timeout
        self.requests = 0

    def request(self, url, *, method="GET", headers=None, body=None) -> HttpResponse:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            raise ValidationError("Malformed HTTPS URL") from None
        if (
            parsed.scheme != "https"
            or parsed.hostname not in self.allowed_hosts
            or port not in (None, 443)
            or parsed.username
            or parsed.password
            or parsed.fragment
            or re.search(r"[\x00-\x20\x7f]", url)
            or method not in ("GET", "POST")
        ):
            raise ValidationError("HTTPS request is outside exact approved host scope")
        if self.allow_partial_body and method != "GET":
            raise ValidationError("Partial response collection is restricted to GET")
        endpoints = {("api.openai.com", "/v1/responses"), ("api.osv.dev", "/v1/querybatch")}
        if method == "POST" and ((parsed.hostname, parsed.path) not in endpoints or parsed.query):
            raise ValidationError("POST is restricted to supported model/advisory query endpoints")
        if self.requests >= self.max_requests:
            raise ProviderError("HTTP request budget exhausted")
        address = public_address(parsed.hostname)
        self.requests += 1
        connection = _PinnedHTTPS(parsed.hostname, address, self.timeout)
        try:
            connection.request(
                method,
                parsed.path + ("?" + parsed.query if parsed.query else ""),
                body=body,
                headers={"User-Agent": f"AI-Threat-Lab/{__version__}", **(headers or {})},
            )
            response = connection.getresponse()
            items = tuple((key.lower(), value) for key, value in response.getheaders())
            data, body_status = self._read_body(response)
            return HttpResponse(response.status, dict(items), data, items, body_status)
        except (OSError, http.client.HTTPException):
            raise ProviderError("HTTPS request failed; no automatic retry was performed") from None
        finally:
            connection.close()

    def _read_body(self, response):
        remaining = getattr(response, "length", None)
        if self.allow_partial_body and type(remaining) is int and remaining > self.max_bytes:
            return b"", "size_limit"
        try:
            data = response.read(self.max_bytes + 1)
        except (OSError, http.client.HTTPException):
            if not self.allow_partial_body:
                raise
            return b"", "read_error"
        if len(data) > self.max_bytes:
            if not self.allow_partial_body:
                raise ProviderError("Provider response exceeded the size limit")
            return b"", "size_limit"
        # Bounded HTTPResponse.read(amt) can return short without IncompleteRead.
        if getattr(response, "length", None) not in (None, 0):
            if not self.allow_partial_body:
                raise ProviderError("Provider response body is incomplete")
            return b"", "read_error"
        return data, "complete"


def get_document(client, url, headers=None) -> dict:
    response = client.request(url, headers=headers)
    if response.status != 200:
        raise ProviderError(f"Read-only provider returned HTTP {response.status}")
    return response.document()
