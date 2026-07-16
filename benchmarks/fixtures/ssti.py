"""Minimized SSTI shapes for fixture discrimination (not ground truth)."""

from jinja2 import Environment, Template, select_autoescape
from jinja2.sandbox import SandboxedEnvironment, ImmutableSandboxedEnvironment
from flask import render_template_string


def vulnerable_plain_environment(user_template: str) -> str:
    env = Environment(autoescape=select_autoescape(default=False))
    return env.from_string(user_template).render()


def vulnerable_template_ctor(user_template: str) -> str:
    return Template(user_template).render()


def vulnerable_flask_string(user_template: str) -> str:
    return render_template_string(user_template)


def patched_sandboxed(user_template: str) -> str:
    env = SandboxedEnvironment()
    return env.from_string(user_template).render()


def patched_immutable(user_template: str) -> str:
    env = ImmutableSandboxedEnvironment()
    return env.from_string(user_template).render()


def patched_alias_import(user_template: str) -> str:
    from jinja2.sandbox import SandboxedEnvironment as Environment

    env = Environment()
    return env.from_string(user_template).render()
