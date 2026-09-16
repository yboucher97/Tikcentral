import asyncio
import ipaddress
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.getenv("DB_PATH", "/var/lib/tikcentral/tikcentral.db")
BIND_HOST = os.getenv("WINBOX_BIND_HOST", "0.0.0.0")
TARGET_PORT = int(os.getenv("WINBOX_TARGET_PORT", "8291"))


def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def authorized(source_ip: str) -> bool:
    try:
        ip = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    if ip.version != 4:
        return False

    now = datetime.now(timezone.utc).isoformat()
    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT 1 FROM authorized_ips
            WHERE ip_address=? AND (always_allow=1 OR (expires_at IS NOT NULL AND expires_at>?))
            LIMIT 1
            """,
            (str(ip), now),
        ).fetchone()
    return bool(row)


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, vpn_ip: str):
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else ""
    if not authorized(source_ip):
        writer.close()
        await writer.wait_closed()
        return

    try:
        target_reader, target_writer = await asyncio.wait_for(
            asyncio.open_connection(vpn_ip, TARGET_PORT), timeout=8
        )
    except Exception:
        writer.close()
        await writer.wait_closed()
        return

    async def pipe(src, dst):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    await asyncio.gather(pipe(reader, target_writer), pipe(target_reader, writer))


def router_ports():
    with db_connect() as conn:
        return conn.execute(
            "SELECT vpn_ip,public_winbox_port FROM routers WHERE enabled=1 AND public_winbox_port IS NOT NULL"
        ).fetchall()


async def main():
    servers = []
    for row in router_ports():
        port = int(row["public_winbox_port"])
        vpn_ip = row["vpn_ip"]
        server = await asyncio.start_server(
            lambda r, w, target=vpn_ip: relay(r, w, target), BIND_HOST, port
        )
        servers.append(server)
        print(f"WinBox proxy {port} -> {vpn_ip}:{TARGET_PORT}", flush=True)

    if not servers:
        print("No router WinBox ports configured; proxy waiting.", flush=True)
        while True:
            await asyncio.sleep(3600)

    await asyncio.gather(*(server.serve_forever() for server in servers))


if __name__ == "__main__":
    asyncio.run(main())
