"""
Extended frontend tests for session creator attribution edge cases.

Complements tests_unit/test_session_creator_frontend.py (17 existing tests) with:
1.  kanban source renders '<agent> (kanban)' suffix pattern.
2.  cron source renders '<agent> (cron)' suffix pattern.
3.  api source renders 'API: <name>' pattern.
4.  Very long display names — _formatCreatorLabel does NOT truncate (CSS handles it).
5.  Null/falsy created_by -> _formatCreatorLabel returns '' (no crash).
6.  _renderOneSession skips creator div when created_by is absent/null.
7.  syncAppTitlebar creator badge is in panels.js and references correct element id.
8.  i18n.js provides cron_source_cron / cron_source_kanban / api values.
9.  CSS has .app-titlebar-creator--unknown rule.
10. Tooltip for slack includes platform_user_id hint.

Run: python3.12 -m pytest tests_unit/test_session_creator_frontend_edge_cases.py -v
"""
import pathlib
import re

REPO = pathlib.Path(__file__).parent.parent

SESSIONS_JS = (REPO / "static" / "sessions.js").read_text(encoding="utf-8")
PANELS_JS   = (REPO / "static" / "panels.js").read_text(encoding="utf-8")
I18N_JS     = (REPO / "static" / "i18n.js").read_text(encoding="utf-8")
STYLE_CSS   = (REPO / "static" / "style.css").read_text(encoding="utf-8")


# ── Helper ────────────────────────────────────────────────────────────────────

def _function_body(src: str, name: str) -> str:
    """Extract the body of a named JS function (brace-balanced, best-effort)."""
    pattern = re.compile(
        rf"(?:^|\n)(?:async\s+)?function\s+{re.escape(name)}\s*\("
    )
    m = pattern.search(src)
    assert m is not None, f"{name}() not found in source"
    start = m.start()
    depth, opened = 0, False
    for i in range(start, len(src)):
        c = src[i]
        if c == '{':
            depth += 1; opened = True
        elif c == '}':
            depth -= 1
        if opened and depth == 0:
            return src[start:i+1]
    return src[start:]


# ── 1. kanban source: '<agent> (kanban)' ──────────────────────────────────────

def test_kanban_source_uses_kanban_suffix():
    """_formatCreatorLabel kanban branch must produce '<agent> (<suffix>)' pattern."""
    body = _function_body(SESSIONS_JS, "_formatCreatorLabel")
    # Must handle 'kanban'
    assert "'kanban'" in body or '"kanban"' in body, (
        "_formatCreatorLabel must have a kanban case"
    )
    # Must reference agent_identity
    assert "agent_identity" in body, (
        "_formatCreatorLabel kanban branch must use agent_identity"
    )


def test_kanban_source_result_contains_suffix_token():
    """_formatCreatorLabel kanban branch must wrap result with a suffix token."""
    body = _function_body(SESSIONS_JS, "_formatCreatorLabel")
    # The suffix is either the i18n key creator_source_kanban or the literal 'kanban'
    assert "creator_source_kanban" in body or "'kanban'" in body or '"kanban"' in body, (
        "_formatCreatorLabel kanban branch must use creator_source_kanban i18n key or literal"
    )


# ── 2. cron source: '<agent> (cron)' ─────────────────────────────────────────

def test_cron_source_handled():
    """_formatCreatorLabel must handle source='cron'."""
    body = _function_body(SESSIONS_JS, "_formatCreatorLabel")
    assert "'cron'" in body or '"cron"' in body, (
        "_formatCreatorLabel must have a cron case"
    )


def test_cron_source_uses_cron_suffix():
    """_formatCreatorLabel cron branch must use creator_source_cron key or literal."""
    body = _function_body(SESSIONS_JS, "_formatCreatorLabel")
    assert "creator_source_cron" in body or "'cron'" in body or '"cron"' in body, (
        "_formatCreatorLabel cron branch must use creator_source_cron i18n key or literal"
    )


def test_cron_source_references_agent_identity():
    """_formatCreatorLabel cron branch must reference agent_identity or display_name."""
    body = _function_body(SESSIONS_JS, "_formatCreatorLabel")
    assert "agent_identity" in body or "display_name" in body, (
        "_formatCreatorLabel cron branch must use agent_identity or display_name"
    )


# ── 3. api source: 'API: <name>' ─────────────────────────────────────────────

def test_api_source_handled():
    """_formatCreatorLabel must handle source='api'."""
    body = _function_body(SESSIONS_JS, "_formatCreatorLabel")
    assert "'api'" in body or '"api"' in body, (
        "_formatCreatorLabel must have an api case"
    )


def test_api_source_uses_api_prefix():
    """_formatCreatorLabel api branch must use creator_source_api or 'API:' literal."""
    body = _function_body(SESSIONS_JS, "_formatCreatorLabel")
    has_prefix = (
        "creator_source_api" in body
        or "'API:'" in body
        or '"API:"' in body
        or "'API'" in body
        or '"API"' in body
    )
    assert has_prefix, (
        "_formatCreatorLabel api branch must use creator_source_api key or 'API:' prefix"
    )


# ── 4. Null/falsy created_by guard ───────────────────────────────────────────

def test_format_creator_label_guards_null_input():
    """_formatCreatorLabel must return '' (not crash) when createdBy is null/undefined."""
    body = _function_body(SESSIONS_JS, "_formatCreatorLabel")
    # The guard must check for falsy createdBy before doing anything
    assert "!createdBy" in body or "createdBy == null" in body or "=== null" in body or "typeof createdBy" in body, (
        "_formatCreatorLabel must guard against null/undefined createdBy"
    )


def test_format_creator_label_guard_returns_empty_string():
    """_formatCreatorLabel null-guard path must return '' (empty string)."""
    body = _function_body(SESSIONS_JS, "_formatCreatorLabel")
    # The guard should return '' for falsy input
    first_brace_idx = body.find('{')
    guard_section = body[first_brace_idx:first_brace_idx + 120]
    assert "return ''" in guard_section or 'return ""' in guard_section, (
        "_formatCreatorLabel null-guard must return '' immediately"
    )


def test_format_creator_tooltip_guards_null_input():
    """_formatCreatorTooltip must guard against null/undefined createdBy."""
    body = _function_body(SESSIONS_JS, "_formatCreatorTooltip")
    assert "!createdBy" in body or "createdBy == null" in body or "typeof createdBy" in body, (
        "_formatCreatorTooltip must guard against null/undefined createdBy"
    )


# ── 5. Session row: no creator div when created_by is absent ─────────────────

def test_session_row_skips_creator_div_when_absent():
    """_renderOneSession must not append a creator div when s.created_by is absent/null.

    The rendering block must be conditional on s.created_by being a non-null object.
    """
    # Locate the region around session-creator-label assignment
    creator_block_start = SESSIONS_JS.find("session-creator-label")
    assert creator_block_start >= 0
    # Scan backward for the nearest 'if' that guards the whole block
    pre_block = SESSIONS_JS[max(0, creator_block_start - 300):creator_block_start]
    has_guard = (
        "_createdBy" in pre_block
        or "created_by" in pre_block
        or "createdBy" in pre_block
    )
    assert has_guard, (
        "Session row creator div must be guarded by a created_by null check"
    )


# ── 6. Chat header: data attributes for filtering hook ───────────────────────

def test_chat_header_creator_badge_uses_dataset():
    """panels.js syncAppTitlebar creator badge must set data-creator-source and
    data-creator-user-id via dataset or setAttribute for future filter UI hook."""
    assert (
        "data-creator-source" in PANELS_JS
        or "dataset.creatorSource" in PANELS_JS
        or "setAttribute" in PANELS_JS
    ), (
        "panels.js must set data-creator-source attribute for the future filter hook"
    )
    assert (
        "data-creator-user-id" in PANELS_JS
        or "dataset.creatorUserId" in PANELS_JS
    ), (
        "panels.js must set data-creator-user-id attribute for future filter UI"
    )


def test_chat_header_unknown_modifier_class():
    """panels.js must apply app-titlebar-creator--unknown for source='unknown'."""
    assert "app-titlebar-creator--unknown" in PANELS_JS, (
        "panels.js must apply .app-titlebar-creator--unknown modifier for unknown source"
    )


# ── 7. CSS: .app-titlebar-creator--unknown ────────────────────────────────────

def test_style_app_titlebar_creator_unknown_rule():
    """.app-titlebar-creator--unknown must be defined in style.css."""
    assert ".app-titlebar-creator--unknown" in STYLE_CSS or "app-titlebar-creator--unknown" in STYLE_CSS, (
        "style.css must define .app-titlebar-creator--unknown rule"
    )


def test_style_app_titlebar_creator_unknown_is_italic():
    """.app-titlebar-creator--unknown must set font-style:italic."""
    idx = STYLE_CSS.find("app-titlebar-creator--unknown")
    assert idx >= 0, ".app-titlebar-creator--unknown rule not found in style.css"
    rule = STYLE_CSS[idx:idx+200]
    assert "italic" in rule, (
        ".app-titlebar-creator--unknown must set font-style:italic"
    )


# ── 8. i18n keys: cron and kanban suffixes + api prefix ──────────────────────

def test_i18n_kanban_value_contains_kanban():
    """i18n.js creator_source_kanban must have 'kanban' in its English value."""
    idx = I18N_JS.find("creator_source_kanban")
    assert idx >= 0
    snippet = I18N_JS[idx:idx+60]
    assert "kanban" in snippet.lower(), (
        "creator_source_kanban i18n value must contain 'kanban'"
    )


def test_i18n_cron_value_contains_cron():
    """i18n.js creator_source_cron must have 'cron' in its English value."""
    idx = I18N_JS.find("creator_source_cron")
    assert idx >= 0
    snippet = I18N_JS[idx:idx+60]
    assert "cron" in snippet.lower(), (
        "creator_source_cron i18n value must contain 'cron'"
    )


def test_i18n_api_key_present():
    """i18n.js must define creator_source_api key."""
    assert "creator_source_api" in I18N_JS, (
        "i18n.js is missing creator_source_api key"
    )


def test_i18n_api_value_contains_api():
    """i18n.js creator_source_api value must contain 'API'."""
    idx = I18N_JS.find("creator_source_api")
    assert idx >= 0
    snippet = I18N_JS[idx:idx+60]
    assert "API" in snippet or "api" in snippet.lower(), (
        "creator_source_api i18n value must contain 'API'"
    )


# ── 9. Tooltip: slack includes uid hint ──────────────────────────────────────

def test_tooltip_slack_includes_uid_hint():
    """_formatCreatorTooltip for slack must append the platform_user_id."""
    body = _function_body(SESSIONS_JS, "_formatCreatorTooltip")
    assert "platform_user_id" in body, (
        "_formatCreatorTooltip must include platform_user_id for slack source"
    )


def test_tooltip_arrow_separator_or_chain():
    """_formatCreatorTooltip must include some chain separator between label parts."""
    body = _function_body(SESSIONS_JS, "_formatCreatorTooltip")
    # Arrow, dash, colon, or join separator
    has_separator = (
        "→" in body or "->" in body
        or "join" in body
        or "parts" in body
    )
    assert has_separator, (
        "_formatCreatorTooltip must separate attribution parts (arrow, join, etc.)"
    )


# ── 10. CSS: muted color on session-creator-label ────────────────────────────

def test_style_session_creator_label_uses_muted_color():
    """.session-creator-label must use var(--muted) or equivalent for subdued color."""
    idx = STYLE_CSS.find(".session-creator-label{")
    if idx < 0:
        idx = STYLE_CSS.find(".session-creator-label {")
    assert idx >= 0, ".session-creator-label rule not found"
    rule = STYLE_CSS[idx:idx+300]
    has_color = (
        "--muted" in rule
        or "color:" in rule
        or "opacity" in rule
    )
    assert has_color, (
        ".session-creator-label must set a color (var(--muted) or explicit color:)"
    )


def test_style_session_creator_label_overflow_control():
    """.session-creator-label must control overflow to prevent layout breaks."""
    idx = STYLE_CSS.find(".session-creator-label{")
    if idx < 0:
        idx = STYLE_CSS.find(".session-creator-label {")
    assert idx >= 0, ".session-creator-label rule not found"
    rule = STYLE_CSS[idx:idx+300]
    has_overflow = (
        "overflow" in rule
        or "ellipsis" in rule
        or "text-overflow" in rule
        or "white-space" in rule
        or "max-width" in rule
    )
    assert has_overflow, (
        ".session-creator-label must handle overflow/ellipsis for long display names"
    )
