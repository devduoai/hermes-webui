"""
Tests for the session creator attribution frontend (sessions.js, panels.js, i18n.js, style.css).

Asserts:
1. _formatCreatorLabel function is defined in sessions.js.
2. A session with source='webui' renders the display_name (email) label.
3. A session with source='slack' renders 'Slack: <name>'.
4. A session with source='unknown' renders italic 'unknown' (class check).
5. Tooltip (_formatCreatorTooltip) contains source breakdown.
6. session-creator-label div is appended in _renderOneSession.
7. Chat header (syncAppTitlebar) sets data-creator-source and data-creator-user-id attributes.
8. i18n.js contains creator_source_slack, creator_source_kanban, creator_source_cron,
   creator_source_unknown, creator_source_api keys.
9. style.css contains .session-creator-label and .app-titlebar-creator rules.
"""
import pathlib
import re

REPO = pathlib.Path(__file__).parent.parent

SESSIONS_JS = (REPO / "static" / "sessions.js").read_text(encoding="utf-8")
PANELS_JS   = (REPO / "static" / "panels.js").read_text(encoding="utf-8")
I18N_JS     = (REPO / "static" / "i18n.js").read_text(encoding="utf-8")
STYLE_CSS   = (REPO / "static" / "style.css").read_text(encoding="utf-8")


# ── Helper to extract a function body from JS source ─────────────────────────

def _function_body(src: str, name: str) -> str:
    """Extract the body of a named JS function (best-effort, brace-balanced)."""
    pattern = re.compile(
        rf"(?:^|\n)(?:async\s+)?function\s+{re.escape(name)}\s*\("
    )
    m = pattern.search(src)
    assert m is not None, f"{name}() not found in source"
    start = m.start()
    depth = 0
    i = start
    opened = False
    while i < len(src):
        c = src[i]
        if c == '{':
            depth += 1
            opened = True
        elif c == '}':
            depth -= 1
        if opened and depth == 0:
            return src[start:i+1]
        i += 1
    return src[start:]


# ── 1. _formatCreatorLabel is defined ─────────────────────────────────────────

def test_format_creator_label_defined():
    """_formatCreatorLabel must be defined in sessions.js."""
    assert "_formatCreatorLabel" in SESSIONS_JS, (
        "_formatCreatorLabel() not found in sessions.js"
    )


# ── 2. webui source renders email / display_name ─────────────────────────────

def test_webui_source_renders_display_name():
    """_formatCreatorLabel must handle source='webui' and return display_name."""
    body = _function_body(SESSIONS_JS, "_formatCreatorLabel")
    assert "'webui'" in body or '"webui"' in body, (
        "_formatCreatorLabel must handle source='webui'"
    )
    assert "display_name" in body, (
        "_formatCreatorLabel webui branch must reference display_name"
    )


# ── 3. slack source renders 'Slack: <name>' ───────────────────────────────────

def test_slack_source_renders_prefix_and_name():
    """_formatCreatorLabel must handle source='slack' and use the slack i18n prefix."""
    body = _function_body(SESSIONS_JS, "_formatCreatorLabel")
    assert "'slack'" in body or '"slack"' in body, (
        "_formatCreatorLabel must handle source='slack'"
    )
    # Must reference the i18n key or hard-coded 'Slack:' fallback
    assert "creator_source_slack" in body or "'Slack:'" in body or '"Slack:"' in body, (
        "_formatCreatorLabel slack branch must use creator_source_slack key or 'Slack:' fallback"
    )


# ── 4. unknown source adds --unknown class ────────────────────────────────────

def test_unknown_source_unknown_modifier_class():
    """session-creator-label--unknown CSS modifier must be applied for source='unknown'."""
    # Check the JS renders the --unknown modifier class
    assert "session-creator-label--unknown" in SESSIONS_JS, (
        "sessions.js must apply .session-creator-label--unknown for source='unknown'"
    )
    # Check the CSS rule exists
    assert "session-creator-label--unknown" in STYLE_CSS, (
        "style.css must define .session-creator-label--unknown rule"
    )
    # The CSS rule must include font-style:italic
    rule_start = STYLE_CSS.find("session-creator-label--unknown")
    rule = STYLE_CSS[rule_start:rule_start+200]
    assert "italic" in rule, (
        ".session-creator-label--unknown must have font-style:italic"
    )


# ── 5. Tooltip function defined and includes source breakdown ─────────────────

def test_format_creator_tooltip_defined():
    """_formatCreatorTooltip must be defined in sessions.js."""
    assert "_formatCreatorTooltip" in SESSIONS_JS, (
        "_formatCreatorTooltip() not found in sessions.js"
    )

def test_tooltip_references_label():
    """_formatCreatorTooltip must call _formatCreatorLabel for the base label."""
    body = _function_body(SESSIONS_JS, "_formatCreatorTooltip")
    assert "_formatCreatorLabel" in body, (
        "_formatCreatorTooltip must call _formatCreatorLabel for the base label"
    )


# ── 6. Sidebar _renderOneSession appends creator label div ───────────────────

def test_sidebar_appends_creator_label():
    """_renderOneSession must create a .session-creator-label div and append it."""
    # The function is a nested function; search for the class name in sessions.js
    assert "session-creator-label" in SESSIONS_JS, (
        "sessions.js must reference 'session-creator-label' class in the session row renderer"
    )
    # Ensure it calls _formatCreatorLabel
    assert "_formatCreatorLabel" in SESSIONS_JS, (
        "sessions.js must call _formatCreatorLabel in session row rendering"
    )
    # Ensure it sets title attribute (tooltip)
    # Search for the block that sets .title on the creator element
    creator_block_idx = SESSIONS_JS.find("session-creator-label")
    assert creator_block_idx >= 0
    block = SESSIONS_JS[creator_block_idx:creator_block_idx + 500]
    assert ".title" in block or "creatorEl.title" in SESSIONS_JS[creator_block_idx:creator_block_idx + 800], (
        "session row creator element must set .title for tooltip"
    )


# ── 7. Chat header sets data-creator-source and data-creator-user-id ──────────

def test_chat_header_data_creator_source():
    """syncAppTitlebar must set data-creator-source attribute on the creator badge."""
    assert "data-creator-source" in PANELS_JS or "creatorSource" in PANELS_JS or "dataset.creatorSource" in PANELS_JS, (
        "panels.js syncAppTitlebar must set data-creator-source on the creator badge element"
    )

def test_chat_header_data_creator_user_id():
    """syncAppTitlebar must set data-creator-user-id attribute on the creator badge."""
    assert "data-creator-user-id" in PANELS_JS or "creatorUserId" in PANELS_JS or "dataset.creatorUserId" in PANELS_JS, (
        "panels.js syncAppTitlebar must set data-creator-user-id on the creator badge element"
    )

def test_chat_header_creator_badge_id():
    """syncAppTitlebar must create/reference the appTitlebarCreator element."""
    assert "appTitlebarCreator" in PANELS_JS, (
        "panels.js must reference appTitlebarCreator element id for creator badge"
    )


# ── 8. i18n.js contains all required creator source keys ─────────────────────

_REQUIRED_I18N_KEYS = [
    "creator_source_slack",
    "creator_source_kanban",
    "creator_source_cron",
    "creator_source_unknown",
    "creator_source_api",
]

def test_i18n_creator_keys_present():
    """i18n.js English locale must define all required creator_source_* keys."""
    for key in _REQUIRED_I18N_KEYS:
        assert key in I18N_JS, (
            f"i18n.js is missing required key: {key!r}"
        )

def test_i18n_slack_value_contains_slack():
    """i18n.js creator_source_slack must have 'Slack' in its English value."""
    # Find the value after the key
    idx = I18N_JS.find("creator_source_slack")
    assert idx >= 0
    snippet = I18N_JS[idx:idx+60]
    assert "Slack" in snippet, (
        "creator_source_slack i18n value must contain 'Slack'"
    )

def test_i18n_unknown_value_contains_unknown():
    """i18n.js creator_source_unknown must have 'unknown' in its English value."""
    idx = I18N_JS.find("creator_source_unknown")
    assert idx >= 0
    snippet = I18N_JS[idx:idx+60]
    assert "unknown" in snippet, (
        "creator_source_unknown i18n value must contain 'unknown'"
    )


# ── 9. style.css has required CSS rules ───────────────────────────────────────

def test_style_session_creator_label_rule():
    """.session-creator-label must be defined in style.css."""
    assert ".session-creator-label" in STYLE_CSS, (
        "style.css must define .session-creator-label rule"
    )

def test_style_app_titlebar_creator_rule():
    """.app-titlebar-creator must be defined in style.css."""
    assert ".app-titlebar-creator" in STYLE_CSS, (
        "style.css must define .app-titlebar-creator rule"
    )

def test_style_session_creator_label_font_size():
    """.session-creator-label must use ~11px font size."""
    idx = STYLE_CSS.find(".session-creator-label{")
    assert idx >= 0, ".session-creator-label rule not found"
    rule = STYLE_CSS[idx:idx+200]
    assert "11px" in rule, ".session-creator-label must use font-size:11px"

def test_style_active_session_creator_color():
    """Active session creator label must have a defined color rule."""
    assert "session-item.active .session-creator-label" in STYLE_CSS, (
        "style.css must define color for active session's .session-creator-label"
    )
