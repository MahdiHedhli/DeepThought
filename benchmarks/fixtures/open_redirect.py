from flask import redirect, request, url_for
from app.helpers import is_safe_redirect_url, safe_redirect


def vulnerable_login():
    next_url = request.args.get("next")
    return redirect(next_url or "/")


def validated_login():
    next_url = request.args.get("next")
    if next_url and is_safe_redirect_url(next_url):
        return redirect(next_url)
    return redirect(url_for("index"))


def wrapper_login():
    return safe_redirect(request, "next", "/")
