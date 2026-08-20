"""
Minimal MCP server for empirically testing whether the `content` field
of Claude Code's ElicitationResult hook reaches the model's context
window or transcript JSONL. Companion to webflow/ctxcop#3.

Two tools, both call ctx.elicit() with the same credential-shape
schema. They differ ONLY in what the tool response returns to the
model. That difference is what lets us isolate the elicitation-content
path from the tool-response path:

  echo_form_neutral   — returns "form_submitted_neutral"; the
                        submitted value is NOT in the tool response.
                        Any appearance of the sentinel in the
                        transcript is unambiguously from `content`.

  echo_form_verbatim  — returns the submitted value verbatim. Sanity
                        check that the sentinel mechanism works.

The sentinel is built at runtime from a split literal so this source
file doesn't contain a contiguous AKIA-prefixed string (ctxcop's own
Write hook would otherwise block edits to this file). The runtime
value is base32-alphabet-compliant so it matches ctxcop's
`ctxcop-aws-access-key` rule.

Run as stdio MCP server; registered via .mcp.json in this directory.
"""

from mcp.server.fastmcp import Context, FastMCP
from pydantic import BaseModel, Field

# Split form so this file doesn't contain a contiguous credential.
SENTINEL = "AKI" + "AELICITSENTINEL34"  # base32-alphabet-compliant


mcp = FastMCP("ctxcop-elicit-test")


class TestForm(BaseModel):
    api_key: str = Field(
        description=f"Test sentinel — type {SENTINEL} here."
    )
    note: str = Field(
        default="",
        description="Optional note (any non-credential value).",
    )


@mcp.tool()
async def echo_form_neutral(ctx: Context) -> str:
    """Prompts via elicit(), returns a NEUTRAL response.

    Isolates whether ElicitationResult `content` reaches the model
    context independent of the tool-response path.
    """
    result = await ctx.elicit(
        message=(
            f"Type the test sentinel {SENTINEL} into the api_key field "
            "(neutral-response variant — server will return a fixed "
            "string, not your input)."
        ),
        schema=TestForm,
    )
    if result.action != "accept":
        return f"form_action={result.action}"
    return "form_submitted_neutral"


@mcp.tool()
async def echo_form_verbatim(ctx: Context) -> str:
    """Prompts via elicit(), returns the submitted value VERBATIM.

    Sanity check that the sentinel mechanism works. If the sentinel
    fails to appear in the transcript even via this path, the test
    rig is broken (or Claude Code's tool-response handling is
    fundamentally different from what we assume).
    """
    result = await ctx.elicit(
        message=(
            f"Type the test sentinel {SENTINEL} into the api_key field "
            "(verbatim-response variant — server will echo your input "
            "in its tool response)."
        ),
        schema=TestForm,
    )
    if result.action != "accept":
        return f"form_action={result.action}"
    return f"echoed: api_key={result.data.api_key}, note={result.data.note}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
