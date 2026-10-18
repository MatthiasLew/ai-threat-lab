"""Bounded HTTPS with exact host scope, pinned public DNS addresses and no redirects."""

import http.client
import ipaddress
import json
import re
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import ValidationError
from .providers import ProviderError


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def document(self) -> dict:
        try:
            result = json.loads(self.body)
            if not isinstance(result, dict):
                raise ValueError
            return result
        except (ValueError, UnicodeError):
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
    def __init__(self, allowed_hosts, *, max_bytes=1024 * 1024, max_requests=110, timeout=15):
        if not 1 <= max_bytes <= 8 * 1024 * 1024 or not 1 <= max_requests <= 200:
            raise ValidationError("Invalid HTTP size or request limit")
        if not 0 < timeout <= 60:
            raise ValidationError("HTTP timeout must be between 0 and 60 seconds")
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
        if method == "POST" and parsed.hostname != "api.openai.com":
            raise ValidationError("POST is restricted to the model response endpoint")
        if method == "POST" and parsed.path != "/v1/responses":
            raise ValidationError("Unsupported model endpoint")
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
                headers={"User-Agent": "AI-Threat-Lab/0.4", **(headers or {})},
            )
            response = connection.getresponse()
            data = response.read(self.max_bytes + 1)
            if len(data) > self.max_bytes:
                raise ProviderError("Provider response exceeded the size limit")
            return HttpResponse(
                response.status, {k.lower(): v for k, v in response.getheaders()}, data
            )
        except (OSError, http.client.HTTPException):
            raise ProviderError("HTTPS request failed; no automatic retry was performed") from None
        finally:
            connection.close()


def get_document(client, url, headers=None) -> dict:
    response = client.request(url, headers=headers)
    if response.status != 200:
        raise ProviderError(f"Read-only provider returned HTTP {response.status}")
    return response.document()
