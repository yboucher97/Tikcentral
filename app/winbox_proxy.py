import asyncio
import ipaddress
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.getenv("DB_PATH", "/var/lib/tikcentral/tikcentral.db")
BIND_HOST = os.getenv("WINBOX_BIND_HOST", "0.0.0.0")
TARGET_PORT = int(os.getenv("WINBOX_TARGET_PORT", "8291"))
RESCAN_SECONDS = int(os.getenv("WINBOX_RESCAN_SECONDS", "10"))


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


def desired_ports() -> dict[int, str]:
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT vpn_ip,public_winbox_port FROM routers WHERE enabled=1 AND public_winbox_port IS NOT NULL"
        ).fetchall()
    return {int(row["public_winbox_port"]): row["vpn_ip"] for row in rows}


async def main():
    servers: dict[int, tuple[str, asyncio.AbstractServer]] = {}
    while True:
        wanted = desired_ports()

        for port, (vpn_ip, server) in list(servers.items()):
            if port not in wanted or wanted[port] != vpn_ip:
                server.close()
                await server.wait_closed()
                del servers[port]
                print(f"Closed WinBox proxy {port}", flush=True)

        for port, vpn_ip in wanted.items():
            if port in servers:
                continue
            try:
                server = await asyncio.start_server(
                    lambda r, w, target=vpn_ip: relay(r, w, target), BIND_HOST, port
                )
            except OSError as exc:
                print(f"Could not bind WinBox proxy {port}: {exc}", flush=True)
                continue
            servers[port] = (vpn_ip, server)
            print(f"WinBox proxy {port} -> {vpn_ip}:{TARGET_PORT}", flush=True)

        await asyncio.sleep(RESCAN_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
