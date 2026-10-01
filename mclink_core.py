#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCLink —— 我的世界 Java 版 P2P 联机工具（核心库 + Web 控制台）

跨平台：Windows / Linux / macOS / Android（Termux 或 Pydroid3 运行同一份代码）
纯 Python 标准库，无需安装任何第三方包。

联机方式：
  1. 局域网直连辅助（查看本机 IP、自动检测 Java 版开放端口）
  2. IPv6 直连辅助
  3. P2P UDP 打洞联机（打洞失败自动切换服务器中继兜底，转发 TCP）
  4. Web 控制台：手机浏览器打开即可操作（电脑&手机通用界面）

命令行：
  python mclink_core.py info                 # 查看本机网络信息
  python mclink_core.py web [端口]           # 启动 Web 控制台（默认 8765）
  python mclink_core.py create 房间号 --server 信令服务器:端口 [--game-port 25565]
  python mclink_core.py join   房间号 --server 信令服务器:端口 [--listen-port 25565]
"""

import asyncio
import base64
import json
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# 协议常量
# ---------------------------------------------------------------------------

MAGIC = b"MC"                       # 隧道数据包魔数（与信令 JSON 区分）
PKT_PUNCH = 0                       # 打洞探测包
PKT_OPEN = 1                        # 打开一条流；payload: b"t"=TCP / b"u"=UDP
PKT_DATA = 2                        # 流数据
PKT_CLOSE = 3                       # 关闭流；payload 可选错误信息
HDR = struct.Struct("!2sBH")        # 魔数(2) + 类型(1) + 流ID(2)

PUNCH_INTERVAL = 0.3                # 打洞发包间隔（秒）
PUNCH_TIMEOUT = 8.0                 # 打洞超时（秒），超时转中继
KEEPALIVE_INTERVAL = 5.0            # 信令保活间隔（秒）
SIGNAL_RETRY = 5                    # 信令请求重试次数
SIGNAL_RETRY_INTERVAL = 1.0
UDP_SESSION_TTL = 300               # UDP 会话空闲回收（秒）

DEFAULT_SERVER = "127.0.0.1:42339"  # 默认信令服务器（本机测试用，公网部署后请改）


def pack_frame(kind, sid, payload=b""):
    return HDR.pack(MAGIC, kind, sid) + payload


def parse_frame(data):
    """返回 (kind, sid, payload) 或 None"""
    if len(data) >= HDR.size and data[:2] == MAGIC:
        _, kind, sid = HDR.unpack(data[:HDR.size])
        return kind, sid, data[HDR.size:]
    return None


# ---------------------------------------------------------------------------
# 网络信息（跨平台）
# ---------------------------------------------------------------------------

def _run_cmd(cmd):
    """跨编码执行命令：先按 UTF-8 解，失败退回 GBK（中文 Windows）"""
    try:
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        r = subprocess.run(cmd, capture_output=True, timeout=8,
                           creationflags=flags)
        raw = r.stdout or b""
        text = raw.decode("utf-8", errors="ignore")
        if "\ufffd" in text or not text.strip():
            text = raw.decode("gbk", errors="ignore")
        return text
    except Exception:
        return ""


def get_local_ipv4():
    """取本机局域网 IPv4（不发实际数据）"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def get_global_ipv6():
    """取本机全球单播 IPv6（2xxx 开头），没有则返回 None"""
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
        for info in infos:
            addr = info[4][0]
            if addr.startswith(("2", "3")) and "%" not in addr:
                return addr
    except Exception:
        pass
    if sys.platform == "win32":
        out = _run_cmd(["netsh", "interface", "ipv6", "show", "addresses"])
        for line in out.splitlines():
            m = re.search(r"\b(2[0-9a-fA-F:]{10,}|3[0-9a-fA-F:]{10,})\b", line)
            if m:
                return m.group(1)
    return None


def detect_java_ports():
    """自动检测本机 Java 进程（Minecraft）正在监听的 TCP 端口"""
    ports = set()
    if sys.platform == "win32":
        pids = set()
        for img in ("java.exe", "javaw.exe"):
            out = _run_cmd(["tasklist", "/FI", f"IMAGENAME eq {img}",
                            "/FO", "CSV", "/NH"])
            pids |= set(re.findall(r'"[^"]*","(\d+)"', out))
        net = _run_cmd(["netstat", "-ano", "-p", "TCP"])
        for line in net.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[3] == "LISTENING" and parts[4] in pids:
                m = re.search(r":(\d+)$", parts[1])
                if m:
                    ports.add(int(m.group(1)))
    else:
        out = _run_cmd(["ss", "-tlnp"]) or _run_cmd(["netstat", "-tlnp"])
        for line in out.splitlines():
            if "java" in line:
                m = re.search(r":(\d+)\s", line)
                if m:
                    ports.add(int(m.group(1)))
    return sorted(ports)


def network_info():
    """汇总本机联机信息"""
    ip4 = get_local_ipv4()
    ip6 = get_global_ipv6()
    ports = detect_java_ports()
    return {
        "lan_ip": ip4,
        "lan_join": f"{ip4}:25565（同局域网时朋友在多人游戏直接连接里填这个，端口取决于房主局域网开放时显示的端口）",
        "ipv6": ip6 or "（未检测到全球 IPv6，可能运营商未分配）",
        "java_ports": ports,
        "java_ports_text": ", ".join(map(str, ports)) if ports else "未检测到（请先在 MC 里对局域网开放世界）",
    }


# ---------------------------------------------------------------------------
# 隧道核心
# ---------------------------------------------------------------------------

class _UdpProto(asyncio.DatagramProtocol):
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.tunnel.on_datagram(data, addr)

    def error_received(self, exc):
        pass


class _UpstreamUdpProto(asyncio.DatagramProtocol):
    """房主侧连到真实游戏端口的上游 UDP 端点：把游戏回包送回隧道"""

    def __init__(self, tunnel, sid):
        self.tunnel = tunnel
        self.sid = sid

    def datagram_received(self, data, addr):
        self.tunnel.on_upstream_udp(self.sid, data)


class _LocalUdpProto(asyncio.DatagramProtocol):
    """游戏客户端一侧的本地 UDP 监听（基岩版用，Java 版不经过这里）"""

    def __init__(self, tunnel):
        self.tunnel = tunnel
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.tunnel.on_local_udp(data, addr)


class Tunnel:
    """
    一条 P2P 隧道会话。

    角色：
      host  —— 房主：接收玩家发来的流，转发到本机游戏端口
      guest —— 玩家：本地开监听端口，把游戏流量打进隧道送给房主
    """

    def __init__(self, app, role, room, pw, server, *,
                 listen_port=None, target_port=None,
                 udp_listen_port=None, udp_target_port=None):
        self.app = app
        self.log = app.log
        self.role = role
        self.room = room
        self.pw = pw or ""
        self.server = server                      # (ip, port)
        self.listen_port = listen_port            # guest: 本地 TCP 监听
        self.target_port = target_port or 25565   # host: 本机游戏端口
        self.udp_listen_port = udp_listen_port    # guest: 本地 UDP 监听
        self.udp_target_port = udp_target_port    # host: 本机游戏 UDP 端口
        self.transport = None
        self.peers = {}            # peer_str -> {"direct": bool, "last": ts}
        self.streams = {}          # sid -> dict
        self.udp_sessions = {}     # guest侧: 本地addr -> sid;  host侧: sid -> transport
        self.udp_last = {}         # sid -> ts
        self.use_relay = False     # 发送是否走服务器中继
        self.stopped = False
        self._tasks = set()
        self._sid_prefix = random.randint(1, 255) << 8
        self._sid_counter = 0
        self._ack = None           # 信令应答 future
        self.started_at = time.time()
        self.host_peer = None      # guest 的对端（房主公网映射）

    # ---------- 状态上报 ----------

    def set_status(self, text):
        self.app.set_status(text)

    # ---------- 生命周期 ----------

    async def run(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProto(self), local_addr=("0.0.0.0", 0))
        my_port = self.transport.get_extra_info("sockname")[1]
        self.log(f"隧道 UDP 套接字已就绪（本地端口 {my_port}）")

        # 1. 信令：注册房间
        action = "create" if self.role == "host" else "join"
        ack = await self._signal(action)
        if ack is None:
            self.set_status("信令失败：连不上信令服务器")
            self.log("× 信令服务器无响应，请检查服务器地址是否正确、服务器是否在线")
            await self.close()
            return
        if ack.get("t") == "err":
            self.set_status(f"信令失败：{ack.get('msg', '未知错误')}")
            self.log(f"× 服务器返回错误：{ack.get('msg')}")
            await self.close()
            return

        if self.role == "host":
            self.set_status("房间已创建，等待玩家加入…")
            self.log(f"√ 房间 {self.room} 已创建，把房间号告诉朋友")
        else:
            peer = ack.get("peer", "")
            if peer:
                self.host_peer = peer
                self.peers.setdefault(peer, {"direct": False, "last": 0})
            self.set_status("已找到房主，正在打洞…")
            self.log(f"√ 已加入房间 {self.room}，房主公网映射：{peer}")

        # 2. 打洞 + 保活
        self._spawn(self._keepalive())
        self._spawn(self._punch_loop())

        # 3. 玩家侧开本地监听
        if self.role == "guest":
            if self.listen_port:
                try:
                    srv = await asyncio.start_server(
                        self._on_tcp_client, "0.0.0.0", self.listen_port)
                    self._tasks.add(asyncio.create_task(srv.serve_forever()))
                    self.log(f"√ 本地 TCP 监听 0.0.0.0:{self.listen_port}（在 MC 多人直连里填 127.0.0.1:{self.listen_port}）")
                except OSError as e:
                    self.log(f"× TCP 监听端口 {self.listen_port} 打不开：{e}")
            if self.udp_listen_port:
                try:
                    upt, _ = await loop.create_datagram_endpoint(
                        lambda: _LocalUdpProto(self),
                        local_addr=("0.0.0.0", self.udp_listen_port))
                    self._udp_listen_transport = upt
                    self.log(f"√ 本地 UDP 监听 0.0.0.0:{self.udp_listen_port}")
                except OSError as e:
                    self.log(f"× UDP 监听端口 {self.udp_listen_port} 打不开：{e}")

        # 4. 挂着直到 stop
        while not self.stopped:
            await asyncio.sleep(0.5)

    def _spawn(self, coro):
        t = asyncio.create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def close(self):
        self.stopped = True
        for sid, st in list(self.streams.items()):
            try:
                w = st.get("w")
                if w:
                    w.close()
            except Exception:
                pass
            up = st.get("up")
            if up:
                try:
                    up.close()
                except Exception:
                    pass
        self.streams.clear()
        self.udp_sessions.clear()
        if self.transport:
            self.transport.close()
        self.set_status("已停止")

    # ---------- 信令 ----------

    def _send_json(self, obj):
        try:
            self.transport.sendto(json.dumps(obj).encode("utf-8"), self.server)
        except Exception:
            pass

    async def _signal(self, action):
        """发 create/join 并等应答，带重试"""
        loop = asyncio.get_running_loop()
        msg = {"t": action, "room": self.room, "pw": self.pw}
        for i in range(SIGNAL_RETRY):
            fut = loop.create_future()
            self._ack = fut
            self._send_json(msg)
            try:
                res = await asyncio.wait_for(fut, SIGNAL_RETRY_INTERVAL * 2)
                if isinstance(res, dict) and res.get("t") == "err" and i < SIGNAL_RETRY - 1:
                    # 明确业务错误（房间已存在/密码错误）不重试
                    if res.get("msg") and ("存在" in res["msg"] or "密码" in res["msg"]):
                        return res
                return res
            except asyncio.TimeoutError:
                self.log(f"… 信令无响应，重试 {i + 1}/{SIGNAL_RETRY}")
        return None

    async def _keepalive(self):
        while not self.stopped:
            self._send_json({"t": "ping"})
            await asyncio.sleep(KEEPALIVE_INTERVAL)

    # ---------- 数据包入口 ----------

    def on_datagram(self, data, addr):
        addr_s = f"{addr[0]}:{addr[1]}"
        if data[:2] == MAGIC:
            parsed = parse_frame(data)
            if parsed:
                self._on_frame(*parsed, peer=addr_s, via="direct")
            return
        try:
            msg = json.loads(data.decode("utf-8", errors="ignore"))
        except Exception:
            return
        if addr[0] == self.server[0] and addr[1] == self.server[1]:
            self._on_server_msg(msg)

    def _on_server_msg(self, msg):
        t = msg.get("t")
        if t == "ok" or t == "err":
            if self._ack and not self._ack.done():
                self._ack.set_result(msg)
        elif t == "r":
            # 服务器中继的隧道帧
            try:
                frame = base64.b64decode(msg.get("d", ""))
                parsed = parse_frame(frame)
                if parsed:
                    peer = msg.get("from") or "relay"
                    self._on_frame(*parsed, peer=peer, via="relay")
            except Exception:
                pass
        elif t == "peer":
            peer = msg.get("addr", "")
            if peer:
                self.peers.setdefault(peer, {"direct": False, "last": 0})
                self.log(f"√ 玩家加入：{peer}，开始打洞…")
        elif t == "pong":
            pass

    def _on_frame(self, kind, sid, payload, peer, via):
        if via == "direct":
            st = self.peers.setdefault(peer, {"direct": False, "last": 0})
            st["last"] = time.time()
            if not st["direct"]:
                st["direct"] = True
                self.log(f"√ P2P 打洞成功！对端：{peer}（直连）")
                self.set_status("已连接（P2P 直连）")
                if kind == PKT_PUNCH:
                    # 回一个 PUNCH，让对方也确认这条通路是双向可达的
                    try:
                        ip, port = peer.rsplit(":", 1)
                        self.transport.sendto(pack_frame(PKT_PUNCH, 0), (ip, int(port)))
                    except Exception:
                        pass

        if kind == PKT_PUNCH:
            return
        if kind == PKT_OPEN:
            stream_kind = "udp" if payload[:1] == b"u" else "tcp"
            self._spawn(self._on_open(sid, stream_kind, peer))
        elif kind == PKT_DATA:
            st = self.streams.get(sid)
            if st is None:
                # OPEN 还没处理完（异步连接游戏端口中）：先缓冲，防止丢首包
                if self.role == "host":
                    st = self.streams.setdefault(sid, {"peer": peer, "pending": []})
                else:
                    return
            self.udp_last[sid] = time.time()
            if "pending" in st:
                if len(st["pending"]) < 64:      # 缓冲上限，防撑爆内存
                    st["pending"].append(payload)
                return
            w = st.get("w")
            if w:
                try:
                    w.write(payload)
                except Exception:
                    self._close_stream(sid)
            up = st.get("up")
            if up is not None and payload:
                try:
                    up.sendto(payload, st.get("target"))
                except Exception as e:
                    self.log(f"× 上游 UDP 发送失败（流 {sid}）：{e}")
            reply = st.get("reply")
            if reply and payload:
                try:
                    self._udp_listen_transport.sendto(payload, reply)
                except Exception:
                    pass
        elif kind == PKT_CLOSE:
            err = payload.decode("utf-8", errors="ignore")
            self._close_stream(sid)
            if err and self.role == "guest":
                self.log(f"× 房主侧连接游戏失败：{err}")

    # ---------- 打洞 ----------

    async def _punch_loop(self):
        deadline = time.time() + PUNCH_TIMEOUT
        while not self.stopped and time.time() < deadline:
            direct_targets = [p for p, st in self.peers.items() if not st["direct"]]
            if direct_targets:
                frame = pack_frame(PKT_PUNCH, 0)
                for peer in direct_targets:
                    try:
                        ip, port = peer.rsplit(":", 1)
                        self.transport.sendto(frame, (ip, int(port)))
                    except Exception:
                        pass
            if all(st["direct"] for st in self.peers.values()) and self.peers:
                if self.role == "host":
                    self.set_status("已连接（P2P 直连），玩家可以进了")
                else:
                    self.set_status("已连接（P2P 直连）")
                return
            await asyncio.sleep(PUNCH_INTERVAL)
        if not self.stopped and self.peers and not all(st["direct"] for st in self.peers.values()):
            self.use_relay = True
            self.log("… 打洞未成功（可能是对称型 NAT），自动切换服务器中继模式")
            self.set_status("已连接（服务器中继）")

    # ---------- 发送 ----------

    def _alloc_sid(self):
        sid = (self._sid_prefix | (self._sid_counter & 0xFF))
        self._sid_counter += 1
        if self._sid_counter > 0xFF:
            self._sid_prefix = random.randint(1, 255) << 8
            self._sid_counter = 0
        return sid

    def _send_frame(self, kind, sid, payload=b"", peer=None):
        """peer=None 时：guest 发给房主；host 广播给所有对端（一般不需要）"""
        frame = pack_frame(kind, sid, payload)
        targets = [peer] if peer else ([self.host_peer] if self.host_peer else list(self.peers))
        for p in targets:
            st = self.peers.get(p)
            direct = bool(st and st["direct"])
            try:
                if direct and not self.use_relay:
                    ip, port = p.rsplit(":", 1)
                    self.transport.sendto(frame, (ip, int(port)))
                else:
                    msg = {"t": "r", "room": self.room, "d": base64.b64encode(frame).decode()}
                    if self.role == "host" and p and p != "relay":
                        msg["to"] = p
                    self._send_json(msg)
            except Exception:
                pass

    # ---------- TCP 流 ----------

    async def _on_tcp_client(self, reader, writer):
        if self.role != "guest":
            writer.close()
            return
        sid = self._alloc_sid()
        self.streams[sid] = {"w": writer}
        self._send_frame(PKT_OPEN, sid, b"t")
        self.log(f"→ 新连接（流 {sid}），已请求房主接入游戏")
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                if sid in self.streams:
                    self._send_frame(PKT_DATA, sid, data)
            self._send_frame(PKT_CLOSE, sid)
        except Exception:
            self._send_frame(PKT_CLOSE, sid)
        finally:
            self._close_stream(sid)

    async def _on_open(self, sid, stream_kind, peer):
        if self.role != "host":
            return
        self.peers.setdefault(peer, {"direct": False, "last": 0})
        if stream_kind == "tcp":
            # 先建条目带 pending 缓冲，再异步连接游戏端口，避免首包丢失
            st = self.streams.setdefault(sid, {"peer": peer, "pending": []})
            try:
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", self.target_port)
                if self.streams.get(sid) is not st:
                    writer.close()
                    return
                st["w"] = writer
                self.log(f"√ 玩家流 {sid} 已接到本机游戏端口 {self.target_port}")
                for d in st.pop("pending", []):
                    writer.write(d)
                self._spawn(self._host_tcp_pump(sid, reader))
            except Exception as e:
                self.log(f"× 接入本机游戏端口 {self.target_port} 失败：{e}")
                self.log("  提示：房主要先在 MC 里「对局域网开放」，端口不对就在设置里改")
                self.streams.pop(sid, None)
                self._send_frame(PKT_CLOSE, sid, str(e).encode("utf-8")[:200], peer=peer)
        else:
            loop = asyncio.get_running_loop()
            self.streams.setdefault(sid, {"peer": peer, "pending": []})
            try:
                upt, _ = await loop.create_datagram_endpoint(
                    lambda: _UpstreamUdpProto(self, sid),
                    remote_addr=("127.0.0.1", self.udp_target_port or 19132))
                st = self.streams.get(sid)
                if st is None:
                    upt.close()
                    return
                st["up"] = upt
                st["target"] = None
                pend = st.pop("pending", [])
                self.log(f"√ UDP 流 {sid} 已接到本机游戏端口 {self.udp_target_port or 19132}（待发 {len(pend)} 包）")
                for d in pend:
                    upt.sendto(d)
            except Exception as e:
                self.streams.pop(sid, None)
                self._send_frame(PKT_CLOSE, sid, str(e).encode("utf-8")[:200], peer=peer)

    async def _host_tcp_pump(self, sid, reader):
        try:
            while sid in self.streams:
                data = await reader.read(65536)
                if not data:
                    break
                self._send_frame(PKT_DATA, sid, data, peer=self.streams[sid].get("peer"))
            self._send_frame(PKT_CLOSE, sid, peer=self.streams.get(sid, {}).get("peer"))
        except Exception:
            pass
        finally:
            st = self.streams.pop(sid, None)
            if st and st.get("w"):
                try:
                    st["w"].close()
                except Exception:
                    pass

    def _close_stream(self, sid):
        st = self.streams.pop(sid, None)
        if st:
            w = st.get("w")
            if w:
                try:
                    w.close()
                except Exception:
                    pass
            up = st.get("up")
            if up:
                try:
                    up.close()
                except Exception:
                    pass

    # ---------- 本地 UDP（游戏客户端 -> 隧道） ----------

    def on_upstream_udp(self, sid, data):
        """房主侧：真实游戏端口回包 -> 隧道发给玩家"""
        st = self.streams.get(sid)
        if st:
            self.udp_last[sid] = time.time()
            self._send_frame(PKT_DATA, sid, data, peer=st.get("peer"))

    def on_local_udp(self, data, addr):
        if self.role != "guest":
            return
        key = f"{addr[0]}:{addr[1]}"
        sid = self.udp_sessions.get(key)
        if sid is None:
            sid = self._alloc_sid()
            self.udp_sessions[key] = sid
            self._send_frame(PKT_OPEN, sid, b"u")
            self.log(f"→ 本地 UDP 会话 {key}（流 {sid}）")
        self.streams.setdefault(sid, {"reply": addr})
        self.udp_last[sid] = time.time()
        self._send_frame(PKT_DATA, sid, data)


# ---------------------------------------------------------------------------
# 应用封装（GUI / Web / CLI 共用）
# ---------------------------------------------------------------------------

class MCLinkApp:
    """线程安全的封装：内部跑一个 asyncio 事件循环线程"""

    def __init__(self, log=None):
        self._log = log or (lambda s: print(s, flush=True))
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True,
                         name="mclink-loop").start()
        self.tunnel = None
        self.status_text = "空闲"
        self._logbuf = deque(maxlen=300)
        self._lock = threading.Lock()

    def log(self, text):
        line = f"[{time.strftime('%H:%M:%S')}] {text}"
        with self._lock:
            self._logbuf.append(line)
        self._log(text)

    def set_status(self, text):
        self.status_text = text
        self.log("状态：" + text)

    def start(self, role, server, room, pw="", *, target_port=None,
              listen_port=None, udp_listen_port=None, udp_target_port=None):
        """启动隧道。host 需要 target_port；guest 需要 listen_port（Java 版 TCP）"""
        if isinstance(server, str):
            ip, port = server.rsplit(":", 1)
            server = (ip, int(port))
        with self._lock:
            if self.tunnel:
                asyncio.run_coroutine_threadsafe(self.tunnel.close(), self.loop)
                self.tunnel = None
            tp = target_port if role == "host" else None
            lp = listen_port if role == "guest" else None
            ulp = udp_listen_port if role == "guest" else None
            utp = udp_target_port if role == "host" else None
            self.tunnel = Tunnel(self, role, room, pw, server,
                                 listen_port=lp, target_port=tp,
                                 udp_listen_port=ulp, udp_target_port=utp)
            asyncio.run_coroutine_threadsafe(self.tunnel.run(), self.loop)

    def stop(self):
        with self._lock:
            if self.tunnel:
                asyncio.run_coroutine_threadsafe(self.tunnel.close(), self.loop)
                self.tunnel = None
                self.status_text = "空闲"
                self.log("已停止联机")

    @property
    def running(self):
        return self.tunnel is not None

    def snapshot(self):
        with self._lock:
            return {
                "status": self.status_text,
                "running": self.running,
                "log": list(self._logbuf),
                "info": network_info(),
            }


# ---------------------------------------------------------------------------
# Web 控制台（手机浏览器可直接打开操作）
# ---------------------------------------------------------------------------

PAGE = """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>薛朗的联机工具 - 我的世界P2P联机</title>
<style>
  :root { --bg:#f5f7fa; --card:#fff; --tx:#1f2937; --sub:#6b7280; --ac:#2563eb; --ok:#059669; }
  * { box-sizing:border-box; }
  body { margin:0; padding:16px; background:var(--bg); color:var(--tx);
         font-family:system-ui,-apple-system,"Microsoft YaHei",sans-serif; }
  h1 { font-size:20px; margin:0 0 4px; }
  .sub { color:var(--sub); font-size:13px; margin-bottom:14px; }
  .card { background:var(--card); border-radius:12px; padding:14px; margin-bottom:12px;
          box-shadow:0 1px 4px rgba(0,0,0,.08); }
  label { display:block; font-size:13px; color:var(--sub); margin:8px 0 3px; }
  input, select { width:100%; padding:9px 10px; border:1px solid #d1d5db; border-radius:8px;
                  font-size:15px; background:#fff; color:var(--tx); }
  .row { display:flex; gap:8px; }
  .row > * { flex:1; }
  button { width:100%; padding:11px; margin-top:10px; border:0; border-radius:8px;
           font-size:15px; background:var(--ac); color:#fff; }
  button.stop { background:#dc2626; }
  button.ghost { background:#e5e7eb; color:var(--tx); }
  #status { font-size:15px; font-weight:600; }
  pre { background:#0f172a; color:#a5f3fc; padding:10px; border-radius:8px;
        font-size:12px; max-height:220px; overflow:auto; white-space:pre-wrap; }
  .info { font-size:13px; line-height:1.7; color:var(--sub); word-break:break-all; }
  .tag { display:inline-block; background:#e0e7ff; color:#3730a3; border-radius:6px;
         padding:1px 8px; font-size:12px; margin-right:4px; }
</style>
</head>
<body>
<h1>⚡ 薛朗的联机工具</h1>
<div class="sub">MCLink · 我的世界 Java 版 P2P 打洞 · 服务器中继兜底 · 电脑 <div class="sub">P2P 打洞 · 服务器中继兜底 · Java 版（电脑 &amp; FCL 手机）</div>amp; FCL 手机通用</div>

<div class="card">
  <div id="status">加载中…</div>
  <button class="stop" onclick="act('stop')">停止联机</button>
</div>

<div class="card">
  <b>开始联机</b>
  <div class="row">
    <div><label>模式</label>
      <select id="role">
        <option value="host">我是房主（开房间）</option>
        <option value="guest">我是玩家（加入）</option>
      </select></div>
  </div>
  <label>信令服务器（IP:端口）</label>
  <input id="server" placeholder="例如 1.2.3.4:42339">
  <div class="row">
    <div><label>房间号</label><input id="room" placeholder="如 xuelang123"></div>
    <div><label>密码（可空）</label><input id="pw" placeholder="无"></div>
  </div>
  <label>游戏端口</label>
  <input id="port" value="25565">
  <button onclick="act('start')">开始</button>
</div>

<div class="card">
  <b>怎么联机</b>
  <div class="info">
    · <b>房主</b>：MC 内对局域网开放世界 → 上面模式选「房主」→ 开始<br>
    · <b>玩家</b>：模式选「玩家」→ 开始 → 在 MC 多人游戏「直接连接」填
    <span class="tag" id="joinHint">127.0.0.1:25565</span><br>
    · 手机 FCL 玩家同样填这个地址
  </div>
</div>

<div class="card">
  <b>本机信息（局域网/IPv6 直连用）</b>
  <div class="info" id="info">…</div>
  <button class="ghost" onclick="copyJoin()">复制局域网地址</button>
</div>

<div class="card"><b>日志</b><pre id="log">…</pre></div>

<script>
function sel(id){ return document.getElementById(id).value.trim(); }
async function act(a){
  const body = {action:a, role:sel('role'), server:sel('server'), room:sel('room'),
                pw:sel('pw'), port:parseInt(sel('port')||'25565')};
  await fetch('/api/action', {method:'POST', headers:{'Content-Type':'application/json'},
                              body:JSON.stringify(body)});
}
async function copyJoin(){
  try { await navigator.clipboard.writeText(sel('port') ? location.hostname+':'+sel('port') : location.hostname);
        alert('已复制 '+(location.hostname)+':'+sel('port')); } catch(e){}
}
async function poll(){
  try{
    const s = await (await fetch('/api/status')).json();
    document.getElementById('status').textContent = '状态：' + s.status;
    document.getElementById('log').textContent = s.log.join('\\n');
    document.getElementById('info').innerHTML =
      '局域网 IP：<b>'+s.info.lan_ip+'</b><br>'+
      'Java 监听端口：<b>'+s.info.java_ports_text+'</b><br>'+
      'IPv6：<b>'+(s.info.ipv6||'无')+'</b>';
    document.getElementById('joinHint').textContent = '127.0.0.1:'+sel('port');
  }catch(e){}
}
setInterval(poll, 1200); poll();
</script>
</body>
</html>"""


class _WebHandler(BaseHTTPRequestHandler):
    app = None  # type: MCLinkApp

    def _send(self, code, ctype, body):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", PAGE)
        elif self.path == "/api/status":
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(self.app.snapshot(), ensure_ascii=False))
        else:
            self._send(404, "text/plain", "not found")

    def do_POST(self):
        if self.path != "/api/action":
            self._send(404, "text/plain", "not found")
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            msg = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._send(400, "application/json", '{"ok":false,"msg":"参数错误"}')
            return
        action = msg.get("action")
        if action == "stop":
            self.app.stop()
            self._send(200, "application/json; charset=utf-8",
                       json.dumps({"ok": True}, ensure_ascii=False))
        elif action == "start":
            role = msg.get("role", "guest")
            server = msg.get("server") or DEFAULT_SERVER
            room = msg.get("room") or f"room{random.randint(1000, 9999)}"
            pw = msg.get("pw", "")
            port = int(msg.get("port") or 25565)
            self.app.log(f"Web 控制台操作：{'开房间' if role == 'host' else '加入'} "
                         f"服务器={server} 房间={room}")
            self.app.start(role, server, room, pw,
                           target_port=port, listen_port=port)
            self._send(200, "application/json; charset=utf-8",
                       json.dumps({"ok": True, "room": room}, ensure_ascii=False))
        else:
            self._send(400, "application/json; charset=utf-8",
                       json.dumps({"ok": False, "msg": "未知操作"}, ensure_ascii=False))

    def log_message(self, fmt, *args):
        pass  # 静默访问日志


def start_web_console(app, port=8765):
    """在后台线程启动 Web 控制台，返回 (httpd, 实际端口)"""
    handler = type("H", (_WebHandler,), {"app": app})
    httpd = ThreadingHTTPServer(("0.0.0.0", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


# ---------------------------------------------------------------------------
# 命令行入口
# ---------------------------------------------------------------------------

def _fix_win_console():
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main():
    _fix_win_console()
    import argparse
    p = argparse.ArgumentParser(description="MCLink 我的世界 P2P 联机核心")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("info", help="查看本机网络信息")
    w = sub.add_parser("web", help="启动 Web 控制台（手机可操作）")
    w.add_argument("port", nargs="?", type=int, default=8765)

    for name, role in (("create", "host"), ("join", "guest")):
        c = sub.add_parser(name, help="开房间（房主）" if role == "host" else "加入房间（玩家）")
        c.add_argument("room", help="房间号")
        c.add_argument("--server", default=DEFAULT_SERVER, help="信令服务器 IP:端口")
        c.add_argument("--pw", default="", help="房间密码")
        c.add_argument("--port", type=int, default=25565,
                       help="房主=本机游戏端口 / 玩家=本地监听端口")

    args = p.parse_args()
    if args.cmd == "info":
        for k, v in network_info().items():
            print(f"{k}: {v}")
        return
    if args.cmd == "web":
        app = MCLinkApp()
        _, real = start_web_console(app, args.port)
        ip = get_local_ipv4()
        print(f"MCLink Web 控制台已启动：")
        print(f"  本机访问：  http://127.0.0.1:{real}")
        print(f"  手机访问：  http://{ip}:{real}   （手机和电脑连同一个 Wi-Fi）")
        print("按 Ctrl+C 退出")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        return
    if args.cmd in ("create", "join"):
        role = "host" if args.cmd == "create" else "guest"
        app = MCLinkApp()
        print(f"MCLink {('房主模式' if role == 'host' else '玩家模式')}："
              f"服务器={args.server} 房间={args.room}")
        if role == "guest":
            print(f"启动后在 MC「直接连接」里填：127.0.0.1:{args.port}")
        app.start(role, args.server, args.room, args.pw,
                  target_port=args.port, listen_port=args.port)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            app.stop()


if __name__ == "__main__":
    main()
