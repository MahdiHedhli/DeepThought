"""Round 3 open-redirect class (CWE-601), deterministic Python AST only."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from openredirect_detector import GROUND_TRUTH_CWE, RULE_ID, scan_file, scan_source

FIXTURE = Path(__file__).parent / "fixtures" / "open_redirect.py"
MANIFEST = Path(__file__).parent / "corpus" / "open_redirect" / "manifest.json"
SEED_CVE = "CVE-2022-0697"


def test_fixture_discriminates_one_vulnerable_redirect():
    assert len(scan_file(FIXTURE, uri=FIXTURE.name)["runs"][0]["results"]) == 1


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "from flask import redirect,request\n"
            "def f(): return redirect(request.args.get('next'))",
            1,
        ),
        (
            "from django.shortcuts import redirect\n"
            "def f(request):\n next_url=request.GET.get('next')\n return redirect(next_url or '/')",
            1,
        ),
        (
            "from django.shortcuts import redirect\n"
            "def f(request): return redirect(request.GET.get('next','/'))",
            1,
        ),
        # Live review: JSON request bodies are request-controlled redirect sources,
        # including async framework accessors.
        (
            "from flask import redirect,request\n"
            "def f(): return redirect(request.json.get('next'))",
            1,
        ),
        (
            "from starlette.responses import RedirectResponse\n"
            "async def f(request):\n payload=await request.json()\n"
            " return RedirectResponse(payload.get('next'))",
            1,
        ),
        # A function-local redirect alias applies only to that lexical scope; it
        # must not bless a same-named call in a sibling function.
        (
            "def f(request):\n from flask import redirect as go\n"
            " return go(request.args.get('next'))\n"
            "def sibling(request): return go(request.args.get('next'))",
            1,
        ),
        (
            "from django.shortcuts import redirect\n"
            "def f(request):\n target=request.GET.get('next')\n target.startswith('/')\n return redirect(target)",
            1,
        ),
        (
            "from django.shortcuts import redirect\n"
            "from django.utils.http import url_has_allowed_host_and_scheme\n"
            "def f(request):\n target=request.GET.get('next')\n"
            " if not url_has_allowed_host_and_scheme(target,{'example'}): raise ValueError\n"
            " return redirect(target)",
            0,
        ),
        (
            "from flask import redirect,request\nfrom app import is_safe_redirect_url\n"
            "def f():\n target=request.args.get('next')\n"
            " if target and is_safe_redirect_url(target): return redirect(target)\n"
            " return redirect('/')",
            0,
        ),
        # Review P2: validation under a composite ``not`` applies to fall-through,
        # never to the rejecting branch.
        (
            "from flask import redirect,request\nfrom app import is_safe_redirect_url\n"
            "def f():\n target=request.args.get('next')\n"
            " if not (target and is_safe_redirect_url(target)):\n  return redirect('/')\n"
            " return redirect(target)",
            0,
        ),
        (
            "from flask import redirect,request\nfrom app import is_safe_redirect_url\n"
            "def f():\n target=request.args.get('next')\n"
            " if not (target and is_safe_redirect_url(target)):\n  return redirect(target)\n"
            " return redirect(target)",
            1,
        ),
        # Boolean implication: OR cannot establish a positive guard; AND cannot
        # establish a negative guard on fall-through.
        (
            "from flask import redirect,request\nfrom app import is_safe_redirect_url\n"
            "def f(debug):\n target=request.args.get('next')\n"
            " if is_safe_redirect_url(target) or debug: return redirect(target)",
            1,
        ),
        (
            "from flask import redirect,request\nfrom app import is_safe_redirect_url\n"
            "def f(debug):\n target=request.args.get('next')\n"
            " if not is_safe_redirect_url(target) and debug: return redirect('/')\n"
            " return redirect(target)",
            1,
        ),
        # An imported validator alias has the same semantics as its original name.
        (
            "from flask import redirect,request\nfrom app import is_safe_redirect_url as check\n"
            "def f():\n target=request.args.get('next')\n"
            " if check(target): return redirect(target)\n return redirect('/')",
            0,
        ),
        (
            "from flask import redirect,request\nfrom app import is_safe_redirect_url\n"
            "def f():\n target=request.args.get('next')\n other=request.args.get('other')\n"
            " if other and is_safe_redirect_url(other): return redirect(target)\n return redirect('/')",
            1,
        ),
        (
            "from flask import redirect,request\nfrom app import is_safe_redirect_url\n"
            "def f():\n target=request.args.get('next')\n is_safe_redirect_url(target)\n return redirect(target)",
            1,
        ),
        (
            "from flask import redirect,request\nfrom app import is_safe_redirect_url\n"
            "def f():\n target=request.args.get('next')\n return redirect(target)\n is_safe_redirect_url(target)",
            1,
        ),
        (
            "from flask import redirect,request\nfrom app import is_safe_redirect_url\n"
            "def f():\n target=request.args.get('next')\n"
            " if target and is_safe_redirect_url(target):\n  target=request.args.get('replacement')\n  return redirect(target)",
            1,
        ),
        (
            "from flask import redirect,request\nfrom app import is_safe_redirect_url\n"
            "def f():\n"
            " def sibling():\n  target=request.args.get('next')\n  return is_safe_redirect_url(target)\n"
            " target=request.args.get('next')\n return redirect(target)",
            1,
        ),
        # Branch assignments merge conservatively at a later sink.
        (
            "from flask import redirect,request\n"
            "def f(flag):\n target='/'\n"
            " if flag: target=request.args.get('next')\n return redirect(target)",
            1,
        ),
        # String formatting preserves request taint.
        (
            "from flask import redirect,request\n"
            "def f(): return redirect('{}'.format(request.args.get('next')))",
            1,
        ),
        # A literal, single-origin path prefix is safe across equivalent string
        # construction forms; a bare or protocol-relative slash prefix is not.
        (
            "from flask import redirect,request\n"
            "def f(): return redirect(f'/dataobj/{request.args.get(\"id\")}')",
            0,
        ),
        (
            "from flask import redirect,request\n"
            "def f(): return redirect('/u/{}'.format(request.args.get('id')))",
            0,
        ),
        (
            "from flask import redirect,request\n"
            "def f(): return redirect('/u/%s' % request.args.get('id'))",
            0,
        ),
        (
            "from flask import redirect,request\n"
            "def f(): return redirect('/{}'.format(request.args.get('next')))",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f(): return redirect('/{0}'.format(request.args.get('next')))",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f(): return redirect('/{}/'.format(request.args.get('next')))",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f(): return redirect('/%s' % request.args.get('next'))",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f(): return redirect('/%(next)s' % {'next': request.args.get('next')})",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f(): return redirect(f'/{request.args.get(\"id\")}')",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f(): return redirect('//' + request.args.get('next'))",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f(): return redirect('///' + request.args.get('next'))",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f(): return redirect('/\\\\' + request.args.get('next'))",
            1,
        ),
        # Review P2: assignment expressions bind before the surrounding branch or
        # redirect call, including when used as a standalone expression.
        (
            "from flask import redirect,request\n"
            "def f():\n if (target := request.args.get('next')):\n  return redirect(target)",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f(): return redirect((target := request.args.get('next')))",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f():\n (target := request.args.get('next'))\n return redirect(target)",
            1,
        ),
        # Framework keyword-only spellings carry the same sink semantics.
        (
            "from flask import redirect,request\n"
            "def f(): return redirect(location=request.args.get('next'))",
            1,
        ),
        (
            "from django.http import HttpResponseRedirect\n"
            "def f(request): return HttpResponseRedirect(redirect_to=request.GET.get('next'))",
            1,
        ),
        (
            "from starlette.responses import RedirectResponse\n"
            "def f(request): return RedirectResponse(url=request.query_params.get('next'))",
            1,
        ),
        (
            "from flask import redirect\ndef f(): return redirect(location='/fixed')",
            0,
        ),
        # Assignments in compound statements must reach a later redirect on every
        # feasible continuation, with may-taint merged across alternative paths.
        (
            "from flask import redirect,request\n"
            "def f():\n target='/'\n with open('x') as fh:\n"
            "  target=request.args.get('next')\n return redirect(target)",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f():\n target='/'\n try:\n  target=request.args.get('next')\n"
            " except Exception:\n  target='/'\n return redirect(target)",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f(items):\n target='/'\n for item in items:\n"
            "  target=request.args.get('next')\n return redirect(target)",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f(flag):\n target='/'\n while flag:\n"
            "  target=request.args.get('next')\n  break\n return redirect(target)",
            1,
        ),
        (
            "from flask import redirect,request\n"
            "def f():\n target=request.args.get('next')\n try:\n  pass\n"
            " finally:\n  target='/'\n return redirect(target)",
            0,
        ),
        ("from flask import redirect\ndef f(): return redirect('/fixed')", 0),
        ("from flask import redirect,url_for\ndef f(): return redirect(url_for('index'))", 0),
        (
            "from django.shortcuts import redirect\ndef f(request): return redirect(request.get_full_path())",
            0,
        ),
        (
            "from app import safe_redirect\ndef f(request): return safe_redirect(request,'next','/')",
            0,
        ),
        (
            "class Worker:\n def redirect(self,url): pass\n def f(self,request): self.redirect(request.url)",
            0,
        ),
        (
            "from tornado import web\nclass H(web.RequestHandler):\n"
            " def get(self): self.redirect(self.request.uri.rstrip('/'))",
            1,
        ),
        (
            "from tornado import web\nclass H(web.RequestHandler):\n"
            " def get(self):\n  path,*rest=self.request.uri.partition('?')\n"
            "  path='/' + path.strip('/')\n  new_uri=''.join([path,*rest])\n  self.redirect(new_uri)",
            0,
        ),
        # Prefixing a raw value with one slash can still produce // or ///. The
        # Jupyter patched shape is safe because strip('/') removes that ambiguity.
        (
            "from flask import redirect,request\n"
            "def f(): return redirect('/' + request.args.get('next'))",
            1,
        ),
        # Nested views are separate scopes, not blind spots or guard donors.
        (
            "from flask import redirect,request\n"
            "def outer():\n def view(): return redirect(request.args.get('next'))\n return view",
            1,
        ),
        (
            "from flask import redirect,request\ndef f():\n"
            " # redirect(request.args.get('next'))\n return redirect('/')",
            0,
        ),
    ],
)
def test_rule_variants(source, expected):
    assert len(scan_source(source, "views.py")) == expected


def test_sarif_carries_cwe_and_only_an_informational_cve_alias():
    sarif = scan_file(FIXTURE, uri=FIXTURE.name, cve=SEED_CVE)
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == RULE_ID
    assert result["properties"] == {"cwe": GROUND_TRUTH_CWE, "cve": SEED_CVE}


def test_full_pipeline_rediscovers_the_seed_shape(tmp_path):
    from deepthought.check import run_check
    from deepthought.export.osv import finding_to_osv, validate_osv
    from deepthought.protocol import HermesUltraCodeGate, run_session
    from deepthought.schema.finding import FindingStatus
    from deepthought.sessions import DiscoverSession, MapSession, NewProjectSession
    from deepthought.store import FileStore

    root = tmp_path / "checkout"
    root.mkdir()
    uri = FIXTURE.name
    (root / uri).write_text(FIXTURE.read_text())
    store = FileStore(str(tmp_path / "state"))
    gate = HermesUltraCodeGate()
    project = "archivy-cve-2022-0697"

    registration = NewProjectSession(
        name="archivy open redirect",
        source_type="open_source",
        local_path=str(root),
        authorization_basis="permissive_oss",
        scope_allowlist=[uri],
        project_id=project,
        verify_url=lambda _url: True,
    )
    assert run_session(store, gate, registration).gate_outcome.value == "proceed"
    run_session(store, gate, MapSession(project, root=str(root)))
    sarif_path = tmp_path / "open-redirect.sarif"
    sarif_path.write_text(json.dumps(scan_file(root / uri, uri=uri, cve=SEED_CVE)))
    run_session(store, gate, DiscoverSession(project, sarif_path=str(sarif_path), root=str(root)))

    findings = store.list_findings(project=project)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.status is FindingStatus.candidate
    assert finding.cve is None
    assert SEED_CVE in finding.aliases
    assert GROUND_TRUTH_CWE in finding.body
    assert validate_osv(finding_to_osv(finding)) == []
    assert run_check(store).ok, run_check(store).errors


def _network_enabled() -> bool:
    if os.environ.get("DEEPTHOUGHT_BENCHMARK_NET") != "1":
        return False
    try:
        socket.create_connection(("raw.githubusercontent.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _network_enabled(), reason="real-tree measurement needs explicit network opt-in")
def test_heldout_generalization_on_real_pinned_trees():
    import sys

    sys.path.insert(0, str(Path(__file__).parent / "harness"))
    from corpus_measure import load_manifest, measure_entry, measure_heldout

    manifest = load_manifest(MANIFEST)
    assert measure_entry(manifest["seed"], scan_source)["rediscovered"]
    result = measure_heldout(manifest, scan_source, RULE_ID)
    assert result.rediscovered == 3
    assert result.missed_cves == []
    assert result.generalization == 1.0
