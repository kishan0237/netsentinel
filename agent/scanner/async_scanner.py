"""Async TCP scanner — much faster than the thread pool for large port ranges."""

import asyncio
from typing import Optional


async def _probe(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> tuple[int, str]:
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return port, "open"
        except ConnectionRefusedError:
            return port, "closed"
        except (asyncio.TimeoutError, OSError):
            return port, "filtered"


async def _scan_ip(ip: str, ports: list[int], timeout: float,
                   concurrency: int) -> list[tuple[int, str]]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(_probe(ip, p, timeout, sem)) for p in ports]
    return await asyncio.gather(*tasks)


def scan_tcp_ports_async(ip: str, ports: list[int], timeout: float = 0.8,
                         concurrency: int = 1000) -> list[dict]:
    """Scan many TCP ports on one host using asyncio. Returns [{port_number, protocol, state}]."""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        pairs = loop.run_until_complete(_scan_ip(ip, ports, timeout, concurrency))
        return [
            {"port_number": p, "protocol": "tcp", "state": s}
            for p, s in sorted(pairs)
        ]
    finally:
        loop.close()


async def scan_hosts_async(ips: list[str], ports: list[int], timeout: float = 0.8,
                           concurrency: int = 1000) -> dict[str, list[dict]]:
    """Scan many hosts concurrently. Returns {ip: [port results]}."""
    sem = asyncio.Semaphore(concurrency)

    async def probe(ip: str, port: int) -> tuple[str, int, str]:
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
                return ip, port, "open"
            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                return ip, port, "filtered"

    tasks = [asyncio.create_task(probe(ip, p)) for ip in ips for p in ports]
    results: dict[str, list[dict]] = {ip: [] for ip in ips}
    for ip, port, state in await asyncio.gather(*tasks):
        if state == "open":
            results[ip].append({"port_number": port, "protocol": "tcp", "state": state})
    for ip in results:
        results[ip].sort(key=lambda r: r["port_number"])
    return results
