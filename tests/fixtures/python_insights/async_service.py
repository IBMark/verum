"""Order status service - blocking calls in async handlers, next to the
async equivalents that must stay silent."""

import asyncio
import subprocess
import time

import httpx
import requests


async def poll_order_status(order_id):
    time.sleep(2)
    status = requests.get(f"https://api.example.com/orders/{order_id}")
    return status.json()


async def export_order(order_id):
    subprocess.run(["generate-invoice", str(order_id)])


async def poll_order_status_async(order_id):
    await asyncio.sleep(2)
    async with httpx.AsyncClient() as client:
        status = await client.get(f"https://api.example.com/orders/{order_id}")
    return status.json()


async def export_order_offloaded(order_id):
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, subprocess.check_call, ["generate-invoice"])


def poll_order_status_sync(order_id):
    time.sleep(5)
    return requests.head(f"https://api.example.com/orders/{order_id}").ok
