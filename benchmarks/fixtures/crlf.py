"""Minimized CRLF / HTTP response-splitting shapes for fixture discrimination."""


def write_header_vuln(header):
    return header[0] + b": " + header[1] + b"\r\n"


def write_header_safe(header):
    def _nocrlf(value: bytes) -> bytes:
        return value.replace(b"\r", b"").replace(b"\n", b"")

    return _nocrlf(header[0]) + b": " + _nocrlf(header[1]) + b"\r\n"


def write_header_safe_named(name: bytes, value: bytes):
    return _safe_header(name) + b": " + _safe_header(value) + b"\r\n"


def _safe_header(value: bytes) -> bytes:
    if b"\r" in value or b"\n" in value:
        raise ValueError("header injection")
    return value


class Response:
    def __init__(self):
        self.headers = {}

    def set_cookie_vuln(self, cookie, value, path=None, domain=None):
        http_cookie = "{cookie}={value}".format(cookie=cookie, value=value)
        if path:
            http_cookie += "; Path=" + path
        if domain:
            http_cookie += "; Domain=" + domain
        if "Set-Cookie" in self.headers:
            self.headers["Set-Cookie"].append(http_cookie)
        else:
            self.headers["Set-Cookie"] = [http_cookie]

    def set_cookie_safe(self, cookie, value, path=None, domain=None):
        http_cookie = "{cookie}={value}".format(cookie=cookie, value=value)
        if path:
            http_cookie += "; Path=" + path
        if domain:
            http_cookie += "; Domain=" + domain
        if "\r" in http_cookie or "\n" in http_cookie:
            raise ValueError("invalid cookie")
        if "Set-Cookie" in self.headers:
            self.headers["Set-Cookie"].append(http_cookie)
        else:
            self.headers["Set-Cookie"] = [http_cookie]
