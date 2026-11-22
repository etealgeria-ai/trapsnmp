"""Run the Trapwell gateway and its console."""

from __future__ import annotations

import asyncio
import logging

from trapwell.service import Service
from trapwell.web import serve


async def _amain() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    service = Service()
    starter = asyncio.create_task(service.start())

    async def _watch() -> None:
        try:
            await starter
        except Exception:
            logging.getLogger("trapwell").exception("gateway start failed")

    asyncio.create_task(_watch())
    await serve(service)


def main() -> None:
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
