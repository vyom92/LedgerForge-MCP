import asyncio
import json
from pathlib import Path

from mcp import Client


MCP_PATH = Path(".mcp-path").read_text().strip()
URL = f"http://127.0.0.1:8765{MCP_PATH}"


def show(title, value):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)
    print(json.dumps(value, indent=2, default=str))


async def call(client, name, args):
    result = await client.call_tool(name, args)

    if result.is_error:
        raise RuntimeError(
            f"{name} failed: {result.content}"
        )

    return result.structured_content


async def main():
    async with Client(URL) as client:
        tools = await client.list_tools()

        show(
            "TOOLS",
            [tool.name for tool in tools.tools],
        )

        show(
            "REPOSITORY STATE",
            await call(
                client,
                "repository_state",
                {},
            ),
        )

        show(
            "AXIS FILES",
            await call(
                client,
                "list_repo_files",
                {
                    "glob": "*AxisCreditCard*",
                    "max_results": 50,
                },
            ),
        )

        show(
            "AXIS SEARCH",
            await call(
                client,
                "search_repo",
                {
                    "query": "AxisCreditCard",
                    "case_sensitive": False,
                    "max_results": 8,
                },
            ),
        )

        show(
            "XLSX PARSER READ",
            await call(
                client,
                "read_file",
                {
                    "path": "Parsers/AxisCreditCardXLSXParser.swift",
                    "start_line": 1,
                    "end_line": 30,
                    "max_bytes": 10000,
                },
            ),
        )

        show(
            "XLSX PARSER DIFF",
            await call(
                client,
                "get_file_diff",
                {
                    "path": "Parsers/AxisCreditCardXLSXParser.swift",
                    "max_bytes": 6000,
                },
            ),
        )

        show(
            "AGGREGATE DIFF",
            await call(
                client,
                "git_diff",
                {
                    "max_bytes": 6000,
                },
            ),
        )


asyncio.run(main())
