#!/usr/bin/env python3
"""Entry point for GCM MCP Server."""

from src.server import main
import asyncio

if __name__ == "__main__":
    asyncio.run(main())
