"""The resource_summary renderer for gh_delete_repo over the real tools/github.yaml."""

from __future__ import annotations

from agentpass.preview import Unavailable
from agentpass.services.http import HTTPServiceError
from tests.preview_helpers import build, build_any, fixture, section

ARGS = {"owner": "example-org", "repo": "shiny-app"}


async def _delete(routes):
    return await build("github", "github", "gh_delete_repo", ARGS, routes)


async def test_active_public_repo_lists_facts_and_warnings():
    p = await _delete(
        {"/repos/{owner}/{repo}": fixture("gh/repo_active"), "/search/issues": {"total_count": 3}}
    )
    assert p.title == "Delete repository example-org/shiny-app"
    assert p.summary.startswith("PERMANENTLY DELETE example-org/shiny-app (public, 128 stars")
    assert "PERMANENTLY DELETES example-org/shiny-app" in section(p, "Effect").data
    facts = dict(section(p, "Repository").data)
    assert facts["Stars"] == "128" and facts["Open pull requests"] == "3"
    assert facts["Open issues and PRs"] == "9" and facts["Default branch"] == "main"
    assert "Europe/Berlin" not in facts["Last push"] and "UTC" in facts["Last push"]
    assert "Public repository with 128 stars" in p.warnings
    assert "Not archived" in p.warnings
    assert any("3 open pull request" in w for w in p.warnings)
    assert p.confirm_text == "shiny-app"  # typed confirmation of the repo name
    assert p.digest == p.compute_digest()


async def test_archived_private_fork_has_no_scare_warnings():
    p = await _delete(
        {
            "/repos/{owner}/{repo}": fixture("gh/repo_archived_fork"),
            "/search/issues": {"total_count": 0},
        }
    )
    facts = dict(section(p, "Repository").data)
    assert facts["Fork"] == "yes, of upstream/old" and facts["Archived"] == "yes"
    assert p.warnings == []


async def test_missing_repo_warns_and_still_requires_the_name():
    p = await _delete({})  # every lookup answers HTTP 404
    assert any("Repository not found" in w for w in p.warnings)
    assert [s.label for s in p.sections] == ["Effect"]
    assert p.confirm_text == "shiny-app"


async def test_lookup_failure_keeps_the_preview():
    p = await _delete(
        {
            "/repos/{owner}/{repo}": HTTPServiceError("HTTP 403"),
            "/search/issues": HTTPServiceError("HTTP 403"),
        }
    )
    assert any("details unavailable (HTTP 403)" in w for w in p.warnings)
    assert {n.id: n.status for n in p.lookups} == {"repo_info": "failed", "prs": "failed"}


async def test_hostile_values_are_escaped():
    repo = dict(fixture("gh/repo_active"), default_branch="ma‮in")
    p = await _delete({"/repos/{owner}/{repo}": repo, "/search/issues": {"total_count": 0}})
    assert "‮" not in str(p.to_dict()) and "\\u202e" in str(p.to_dict())


async def test_delete_page_requirement_is_declared():
    result = await build_any("github", "github", "gh_delete_repo", ARGS, {})
    assert not isinstance(result, Unavailable)
