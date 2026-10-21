"""Entry point.

    python -m entra_agent_inventory                     run the MCP server (MCP_TRANSPORT decides how)
    python -m entra_agent_inventory --check             permission self-test, JSON, exit 1 if not ready
"""

import asyncio
import json
import sys


def _check() -> None:
    from .graph import graph
    from .tools import run_access_check

    async def check() -> dict:
        try:
            return await run_access_check()
        except Exception as exc:  # noqa: BLE001 - report, don't traceback
            from .audit import error_payload

            return {"ready": False, **error_payload(exc)}
        finally:
            await graph.close()

    result = asyncio.run(check())
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["ready"] else 1)


def main() -> None:
    argv = sys.argv[1:]
    if "--check" in argv:
        _check()
    else:
        from .server import run

        run()


if __name__ == "__main__":
    main()
