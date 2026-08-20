"""Minimal MCP server for ctxcop issue #80.

Exposes one tool whose RESPONSE contains a credential-shape value that
originates OUTSIDE the model's context. That is the property #80 needs:
PostToolUse must replace the tool_response via updatedToolOutput before
the model sees it. Bash and Read are deliberately skipped by that hook,
so an MCP tool is the smallest path that exercises it.
"""

from mcp.server.fastmcp import FastMCP

# Split-literal so this source file is not itself a contiguous credential.
SENTINEL = "AKIA" + "TESTPOSTTOOLUSE2"

mcp = FastMCP("ctxcop-posttooluse-test")


@mcp.tool()
def fetch_config() -> str:
    """Return a config blob containing an AWS access key id."""
    return f"aws_access_key_id = {SENTINEL}\nregion = us-east-1\n"


if __name__ == "__main__":
    mcp.run()
