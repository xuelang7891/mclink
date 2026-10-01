#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCLink 信令/中继服务器

作用：
  1. 牵线：帮房主和玩家交换公网地址，用于 UDP 打洞（P2P 直连）
  2. 兜底：打洞失败时（对称型 NAT，手机流量常见），原样转发隧道数据（中继模式）

部署要求：一台有【公网 UDP 端口】的服务器（云服务器/VPS 均可）。
  运行：python mclink_server.py [--port 42339]
  防火墙/安全组放行对应 UDP 端口。
注意：一般的"网页托管/函数计算"不支持 UDP，用不了；需要真正的云服务器
  （阿里云/腾讯云轻量、Oracle Cloud 永久免费档等都可以）。

纯 Python 标准库，无任何依赖。
"""

import asyncio
import argparse
import base64
import json
import sys
import time

ROOM_TTL = 30          # 房间成员保活超时（秒），客户端每 5 秒 ping 一次
CLEANUP_INTERVAL = 10

# room -> {"pw": str, "host": addr, "host_seen": ts, "guests": {addr: ts}}
rooms = {}


def alive(ts):
    return time.time() - ts < ROOM_TTL


def addr_str(addr):
    return f"{addr[0]}:{addr[1]}"


class Server:
    def __init__(self, port):
        self.port = port
        self.transport = None

    def send(self, obj, addr):
        try:
            self.transport.sendto(json.dumps(obj).encode("utf-8"), addr)
        except Exception:
            pass

    def send_raw(self, data, addr):
        try:
            self.transport.sendto(data, addr)
        except Exception:
            pass

    def log(self, text):
        print(f"[{time.strftime('%H:%M:%S')}] {text}", flush=True)

    # ---------------- 报文处理 ----------------

    def on_datagram(self, data, addr):
        try:
            msg = json.loads(data.decode("utf-8"))
        except Exception:
            return
        t = msg.get("t")
        if t == "create":
            self.on_create(msg, addr)
        elif t == "join":
            self.on_join(msg, addr)
        elif t == "r":
            self.on_relay(msg, addr)
        elif t == "ping":
            self.on_ping(msg, addr)
        elif t == "leave":
            self.on_leave(msg, addr)

    def on_create(self, msg, addr):
        room = str(msg.get("room", "")).strip()[:64]
        if not room:
            self.send({"t": "err", "msg": "房间号不能为空"}, addr)
            return
        r = rooms.get(room)
        if r and alive(r["host_seen"]):
            self.send({"t": "err", "msg": "房间已存在，换一个房间号"}, addr)
            return
        rooms[room] = {"pw": str(msg.get("pw", "")), "host": addr,
                       "host_seen": time.time(), "guests": {}}
        self.send({"t": "ok", "role": "host"}, addr)
        self.log(f"房间创建：{room}（房主 {addr_str(addr)}）")

    def on_join(self, msg, addr):
        room = str(msg.get("room", "")).strip()[:64]
        r = rooms.get(room)
        if not r or not alive(r["host_seen"]):
            self.send({"t": "err", "msg": "房间不存在或房主不在线"}, addr)
            return
        if r["pw"] != str(msg.get("pw", "")):
            self.send({"t": "err", "msg": "房间密码错误"}, addr)
            return
        r["guests"][addr] = time.time()
        self.send({"t": "ok", "role": "guest", "peer": addr_str(r["host"])}, addr)
        self.send({"t": "peer", "addr": addr_str(addr)}, r["host"])
        self.log(f"玩家加入：{room}（玩家 {addr_str(addr)}）")

    def on_relay(self, msg, addr):
        room = str(msg.get("room", "")).strip()[:64]
        r = rooms.get(room)
        if not r:
            return
        try:
            frame = base64.b64decode(msg.get("d", ""))
        except Exception:
            return
        if not (5 <= len(frame) <= 70000):
            return
        if addr == r["host"]:
            to = msg.get("to")
            if to:
                ip, _, port = str(to).rpartition(":")
                try:
                    self.send_raw(frame, (ip, int(port)))
                    return
                except Exception:
                    pass
            for g in list(r["guests"]):
                if alive(r["guests"].get(g, 0)):
                    self.send_raw(frame, g)
        else:
            if addr in r["guests"]:
                # 发给房主，附上来源，房主才能把回包发对方向
                self.send({"t": "r", "from": addr_str(addr),
                           "d": base64.b64encode(frame).decode()}, r["host"])

    def on_ping(self, msg, addr):
        self.send({"t": "pong"}, addr)
        room = str(msg.get("room", "")).strip()[:64]
        r = rooms.get(room)
        if not r:
            return
        if addr == r["host"]:
            r["host_seen"] = time.time()
        elif addr in r["guests"]:
            r["guests"][addr] = time.time()

    def on_leave(self, msg, addr):
        room = str(msg.get("room", "")).strip()[:64]
        r = rooms.get(room)
        if not r:
            return
        if addr == r["host"]:
            rooms.pop(room, None)
            self.log(f"房主退出，房间关闭：{room}")
        elif addr in r["guests"]:
            r["guests"].pop(addr, None)
            self.log(f"玩家退出：{room}（{addr_str(addr)}）")

    # ---------------- 清理与启动 ----------------

    async def cleanup_loop(self):
        while True:
            await asyncio.sleep(CLEANUP_INTERVAL)
            now = time.time()
            for room in list(rooms):
                r = rooms[room]
                if not alive(r["host_seen"]):
                    rooms.pop(room, None)
                    self.log(f"房间超时回收：{room}")
                    continue
                for g in list(r["guests"]):
                    if not alive(r["guests"][g]):
                        r["guests"].pop(g, None)

    async def run(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: _ServerProto(self), local_addr=("0.0.0.0", self.port))
        self.log(f"MCLink 信令/中继服务器已启动：0.0.0.0:{self.port} (UDP)")
        self.log("提示：记得在云服务器安全组放行该 UDP 端口")
        await self.cleanup_loop()


class _ServerProto(asyncio.DatagramProtocol):
    def __init__(self, server):
        self.server = server

    def connection_made(self, transport):
        self.server.transport = transport

    def datagram_received(self, data, addr):
        self.server.on_datagram(data, addr)

    def error_received(self, exc):
        pass


def main():
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    p = argparse.ArgumentParser(description="MCLink 信令/中继服务器")
    p.add_argument("--port", type=int, default=42339, help="UDP 端口（默认 42339）")
    args = p.parse_args()
    try:
        asyncio.run(Server(args.port).run())
    except KeyboardInterrupt:
        print("已退出", flush=True)


if __name__ == "__main__":
    main()
