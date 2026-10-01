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

DEFAULT_SERVER = "127.0.0.1:42339"  # 自建信令模式默认地址（本机测试用）

# 公共信令（MQTT over 公共 broker，免费、无需注册，用户无需任何服务器）
PUBLIC_BROKERS = [("broker-cn.emqx.io", 1883), ("broker.emqx.io", 1883)]
# STUN 服务器（仅用于探测本机 IPv4 公网映射，不传任何游戏数据）
STUN_SERVERS = [("stun.miwifi.com", 3478), ("stun.qq.com", 3478)]
PUNCH_TIMEOUT_MANUAL = 30.0         # 手动模式打洞等待（双方需同时点开始）


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


_STUN_COOKIE = b"\x21\x12\xa4\x42"
_PUBLIC_IP_CACHE = {"v": None, "t": 0.0}


def _parse_stun_mapped(data, txid):
    """解析 STUN Binding Response，返回公网 "ip:port" 或 None"""
    if len(data) < 20 or data[0:2] != b"\x01\x01" or data[4:8] != _STUN_COOKIE \
            or data[8:20] != txid:
        return None
    i = 20
    while i + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[i:i + 4])
        attr = data[i + 4:i + 4 + alen]
        if atype == 0x0020 and alen >= 8:          # XOR-MAPPED-ADDRESS
            port = struct.unpack("!H", attr[2:4])[0] ^ 0x2112
            ip = socket.inet_ntoa(bytes(a ^ b for a, b in
                                         zip(attr[4:8], _STUN_COOKIE)))
            return f"{ip}:{port}"
        i += 4 + alen
    return None


def get_public_ipv4(timeout=2.5, use_cache=True):
    """通过 STUN 探测本机 IPv4 公网映射地址（仅探测，不传游戏数据）"""
    now = time.time()
    if use_cache and now - _PUBLIC_IP_CACHE["t"] < 600:
        return _PUBLIC_IP_CACHE["v"]
    for host, port in STUN_SERVERS:
        try:
            ip = socket.gethostbyname(host)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            txid = bytes(random.getrandbits(8) for _ in range(12))
            s.sendto(struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txid,
                     (ip, port))
            data, _ = s.recvfrom(1024)
            s.close()
            mapped = _parse_stun_mapped(data, txid)
            if mapped:
                _PUBLIC_IP_CACHE.update(v=mapped, t=now)
                return mapped
        except Exception:
            try:
                s.close()
            except Exception:
                pass
    _PUBLIC_IP_CACHE.update(v=None, t=now)
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


def network_info(include_public=False):
    """汇总本机联机信息"""
    ip4 = get_local_ipv4()
    ip6 = get_global_ipv6()
    ports = detect_java_ports()
    if include_public:
        pub = get_public_ipv4()
    else:
        pub = _PUBLIC_IP_CACHE["v"]
    return {
        "lan_ip": ip4,
        "public_ip": pub or "（探测中或被网络拦截）",
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


class MqttClient:
    """
    极简 MQTT 3.1.1 客户端（纯标准库，asyncio）。
    只实现本工具需要的部分：CONNECT/SUBSCRIBE/PUBLISH(QoS0/1)/PING。
    用途：把公共 MQTT broker 当作免费信令服务器（和游戏数据中继兜底）。
    """

    def __init__(self, host, port, client_id, on_message=None):
        self.host, self.port, self.client_id = host, port, client_id
        self.on_message = on_message      # callable(topic: str, payload: bytes)
        self.reader = self.writer = None
        self.alive = False
        self._pkt_id = 0

    # ---------- 底层 ----------

    @staticmethod
    def _enc_len(n):
        out = b""
        while True:
            d = n % 128
            n //= 128
            if n:
                d |= 0x80
            out += bytes([d])
            if not n:
                return out

    async def _read_packet(self, timeout=None):
        """读一个完整 MQTT 包，超时返回 None"""
        try:
            b1 = await asyncio.wait_for(self.reader.read(1), timeout)
            if not b1:
                raise ConnectionError("连接已关闭")
            hdr = b1
            mult, rem = 1, 0
            while True:
                b = await asyncio.wait_for(self.reader.read(1), timeout)
                if not b:
                    raise ConnectionError("连接已关闭")
                hdr += b
                rem += (b[0] & 0x7F) * mult
                if not b[0] & 0x80:
                    break
                mult *= 128
            body = b""
            while len(body) < rem:
                chunk = await asyncio.wait_for(self.reader.read(rem - len(body)),
                                               timeout)
                if not chunk:
                    raise ConnectionError("连接已关闭")
                body += chunk
            return hdr + body
        except asyncio.TimeoutError:
            return None

    def _next_pid(self):
        self._pkt_id = (self._pkt_id % 0xFFFF) + 1
        return self._pkt_id

    # ---------- 协议 ----------

    async def connect(self, timeout=12):
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port), timeout)
        vh = struct.pack("!H4sBBH", 4, b"MQTT", 4, 0x02, 30)  # 3.1.1 clean session
        cid = self.client_id.encode()
        body = vh + struct.pack("!H", len(cid)) + cid
        self.writer.write(bytes([0x10]) + self._enc_len(len(body)) + body)
        await self.writer.drain()
        pkt = await self._read_packet(timeout)
        if not pkt or pkt[0] >> 4 != 2 or len(pkt) < 3 or pkt[3] != 0:
            raise ConnectionError(f"MQTT 握手被拒绝（{pkt.hex() if pkt else '无响应'}）")
        self.alive = True

    async def subscribe(self, topic, qos=1):
        t = topic.encode()
        body = struct.pack("!H", self._next_pid()) + \
            struct.pack("!H", len(t)) + t + bytes([qos])
        self.writer.write(bytes([0x82]) + self._enc_len(len(body)) + body)
        await self.writer.drain()
        deadline = time.time() + 8
        while time.time() < deadline:
            pkt = await self._read_packet(8)
            if pkt is None:
                break
            if pkt[0] >> 4 == 9:              # SUBACK
                return True
            await self._dispatch(pkt)
        return False

    async def publish(self, topic, payload, qos=0):
        if not self.alive:
            return
        t = topic.encode()
        p = payload if isinstance(payload, bytes) else payload.encode()
        body = struct.pack("!H", len(t)) + t
        if qos:
            body += struct.pack("!H", self._next_pid())
        body += p
        self.writer.write(bytes([0x30 | (qos << 1)]) + self._enc_len(len(body)) + body)
        await self.writer.drain()

    async def loop_forever(self):
        """读包分发 + keepalive，断线后 alive=False"""
        try:
            while self.alive:
                pkt = await self._read_packet(35)
                if pkt is None:
                    self.writer.write(b"\xc0\x00")       # PINGREQ
                    await self.writer.drain()
                    continue
                await self._dispatch(pkt)
        except Exception:
            pass
        finally:
            self.alive = False

    async def _dispatch(self, pkt):
        t = pkt[0] >> 4
        if t == 3:                                        # PUBLISH
            qos = (pkt[0] >> 1) & 0x03
            i = 1
            mult, rem = 1, 0
            while True:
                b = pkt[i]
                rem += (b & 0x7F) * mult
                i += 1
                if not b & 0x80:
                    break
                mult *= 128
            tl = struct.unpack("!H", pkt[i:i + 2])[0]
            i += 2
            topic = pkt[i:i + tl].decode("utf-8", errors="ignore")
            i += tl
            if qos:
                i += 2                                     # packet id
                self.writer.write(bytes([0x40, 0x02]) +
                                  struct.pack("!H", struct.unpack("!H", pkt[i - 2:i])[0]))
            payload = pkt[i:]
            if self.on_message:
                self.on_message(topic, payload)
        # PUBACK(4)/PINGRESP(13) 等无需处理

    def close(self):
        self.alive = False
        try:
            self.writer.close()
        except Exception:
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
                 udp_listen_port=None, udp_target_port=None,
                 sig="udp", broker=None, manual_peer=None, ext=None,
                 punch_timeout=None):
        self.app = app
        self.log = app.log
        self.role = role
        self.room = room
        self.pw = pw or ""
        self.server = server                      # (ip, port)，udp 模式用
        self.listen_port = listen_port            # guest: 本地 TCP 监听
        self.target_port = target_port or 25565   # host: 本机游戏端口
        self.udp_listen_port = udp_listen_port    # guest: 本地 UDP 监听
        self.udp_target_port = udp_target_port    # host: 本机游戏 UDP 端口
        self.sig = sig                            # "udp" | "mqtt" | "manual"
        self.broker = broker                      # mqtt 模式指定 broker，一般留空
        self.manual_peer = manual_peer            # manual 模式：房主公网地址
        self.ext_override = ext                   # 测试用：强制公网地址，"auto"=本地回环
        self.my_ext = None                        # 本机 IPv4 公网映射 "ip:port"
        self.transport = None
        self.peers = {}            # key -> {"direct": bool, "last": ts, "cid": cid}
        self.streams = {}          # sid -> dict
        self.udp_sessions = {}     # guest侧: 本地addr -> sid;  host侧: sid -> transport
        self.udp_last = {}         # sid -> ts
        self.use_relay = False     # 发送是否走服务器中继
        self.stopped = False
        self._tasks = set()
        self._sid_prefix = random.randint(1, 255) << 8
        self._sid_counter = 0
        self._ack = None           # 信令应答 future
        self._stun_fut = None      # STUN 探测应答 (txid, future)
        self.mqtt = None
        self._topic_base = ""
        self.cid = "g" + "".join(random.choices("0123456789abcdef", k=8))
        self.punch_timeout = punch_timeout or (
            PUNCH_TIMEOUT if sig != "manual" else PUNCH_TIMEOUT_MANUAL)
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

        # 0. STUN 探测 IPv4 公网映射（公共信令/手动模式需要）
        if self.sig in ("mqtt", "manual"):
            if self.ext_override == "auto":
                self.my_ext = f"127.0.0.1:{my_port}"          # 测试模式
            elif self.ext_override:
                self.my_ext = self.ext_override
            else:
                self.my_ext = await self._stun_bind()
            if self.my_ext:
                self.log(f"√ 本机 IPv4 公网映射：{self.my_ext}")
            else:
                self.log("… 未能通过 STUN 获取公网地址"
                         "（不影响局域网联机；跨网打洞将依赖中继）")

        # 1. 信令：注册房间
        if self.sig == "udp":
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
        elif self.sig == "mqtt":
            if not await self._mqtt_register():
                await self.close()
                return
        else:  # manual 手动模式
            if self.role == "guest":
                if not self.manual_peer:
                    self.set_status("手动模式：请填写房主公网地址")
                    self.log("× 手动模式需要房主公网地址（房主界面「我的公网地址」）")
                    await self.close()
                    return
                self.peers.setdefault(self.manual_peer, {"direct": False, "last": 0})
                self.set_status("手动模式：正在向房主打洞…")
                self.log(f"√ 目标房主地址：{self.manual_peer}"
                         f"（双方需在 30 秒内先后点开始）")
            else:
                self.set_status("手动模式：等待玩家连入…")
                self.log(f"√ 把你的公网地址发给玩家：{self.my_ext or '（STUN 失败，见日志）'}")
                self.log("  玩家填入后点开始即可；你无需其他操作，等打洞成功")

        # 2. 打洞 + 保活
        if self.sig == "udp":
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
        if self.mqtt:
            self.mqtt.close()
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

    # ---------- STUN（IPv4 公网映射探测） ----------

    async def _stun_bind(self):
        """从隧道同一个 UDP socket 向 STUN 服务器查询公网映射。
        查两个服务器：映射不同 => 对称型 NAT（打洞成功率低，提前告知）。"""
        loop = asyncio.get_running_loop()
        results = []
        for host, port in STUN_SERVERS:
            try:
                ip = await loop.run_in_executor(None, socket.gethostbyname, host)
            except Exception:
                continue
            txid = bytes(random.getrandbits(8) for _ in range(12))
            fut = loop.create_future()
            self._stun_fut = (txid, fut)
            try:
                self.transport.sendto(
                    struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txid, (ip, port))
                mapped = await asyncio.wait_for(fut, 4)
                results.append(mapped)
                if len(results) >= 2 and results[0] != results[1]:
                    self.log("… 两个 STUN 映射不一致：疑似对称型 NAT，"
                             "打洞成功率低，失败会自动切中继")
                    break
            except asyncio.TimeoutError:
                pass
            finally:
                self._stun_fut = None
        return results[0] if results else None

    # ---------- 公共信令（MQTT） ----------

    def _mqtt_publish_json(self, topic, obj, qos=1):
        if self.mqtt and self.mqtt.alive:
            asyncio.create_task(
                self.mqtt.publish(topic, json.dumps(obj, ensure_ascii=False),
                                  qos=qos))

    async def _mqtt_register(self):
        base = self._topic_base = "mclink-p2p/" + \
            re.sub(r"[^a-zA-Z0-9_-]", "", self.room)[:40]
        if not base[len("mclink-p2p/"):]:
            self.set_status("房间号不能为空或全为特殊字符")
            return False
        brokers = [self.broker] if self.broker else PUBLIC_BROKERS
        last_err = None
        for h, p in brokers:
            m = MqttClient(h, p, f"mclink-{self.cid}",
                           on_message=self._mqtt_on_msg)
            try:
                await m.connect()
                self.mqtt = m
                self.log(f"√ 已连上公共信令服务器：{h}（免费公共节点，无需注册）")
                break
            except Exception as e:
                last_err = e
        if not self.mqtt:
            self.set_status("信令失败：连不上公共信令服务器")
            self.log(f"× 公共信令全部连不上：{last_err}（请检查网络）")
            return False

        sub_topics = [f"{base}/host", f"{base}/g/{self.cid}"] \
            if self.role == "host" else [f"{base}/g/{self.cid}"]
        for tp in sub_topics:
            if not await self.mqtt.subscribe(tp):
                self.set_status("信令失败：订阅房间失败")
                self.log("× MQTT 订阅失败（公共节点繁忙？稍后重试或换自建信令）")
                return False
        self._spawn(self.mqtt.loop_forever())

        # 注册（create/join），QoS1 保证送达
        loop = asyncio.get_running_loop()
        action = "create" if self.role == "host" else "join"
        msg = {"t": action, "from": self.cid, "pw": self.pw}
        if self.my_ext:
            msg["ext"] = self.my_ext
        res = None
        if self.role == "host":
            # 房主开房无应答即成功；若该房间已被占用，会收到另一房主的 err
            fut = loop.create_future()
            self._ack = fut
            await self.mqtt.publish(f"{base}/host", json.dumps(msg), qos=1)
            try:
                res = await asyncio.wait_for(fut, 4)
            except asyncio.TimeoutError:
                res = None
            if res and res.get("t") == "err":
                self.set_status(f"信令失败：{res.get('msg', '未知错误')}")
                self.log(f"× {res.get('msg')}")
                return False
        else:
            for attempt in range(3):
                fut = loop.create_future()
                self._ack = fut
                await self.mqtt.publish(f"{base}/host", json.dumps(msg), qos=1)
                try:
                    res = await asyncio.wait_for(fut, 12)
                    break
                except asyncio.TimeoutError:
                    self.log(f"… 没等到房主回应（房主需先开好房间），重试 {attempt + 1}/3")
            if res is None:
                self.set_status("信令失败：房间无响应")
                self.log("× 30 秒无响应：① 双方房间号是否完全一致 ② 房主是否已先点开始")
                return False
            if res.get("t") == "err":
                self.set_status(f"信令失败：{res.get('msg', '未知错误')}")
                self.log(f"× 房主返回错误：{res.get('msg')}")
                return False

        if self.role == "host":
            self.set_status("房间已创建，等待玩家加入…（公共信令）")
            self.log(f"√ 房间 {self.room} 已创建（无需任何服务器！），把房间号告诉朋友")
        else:
            peer = res.get("peer", "")
            if peer:
                self.host_peer = peer
                self.peers.setdefault(peer, {"direct": False, "last": 0})
                self.log(f"√ 已加入房间，房主公网地址：{peer}，开始打洞…")
            else:
                self.log("… 未拿到房主公网地址（房主侧 STUN 受限），将走中继")
            self.set_status("已找到房主，正在打洞…")
        return True

    def _mqtt_on_msg(self, topic, payload):
        try:
            msg = json.loads(payload.decode("utf-8", errors="ignore"))
        except Exception:
            return
        base = self._topic_base
        t = msg.get("t")
        if msg.get("from") == self.cid:
            return                      # 忽略自己的回显
        my_reply = f"{base}/g/{self.cid}"
        if topic == my_reply:
            if t in ("ok", "err") and self._ack and not self._ack.done():
                self._ack.set_result(msg)
            elif t == "r":
                self._on_relay_msg(msg)
            return
        if self.role == "host" and topic == f"{base}/host":
            if t == "join":
                cid = msg.get("from", "")
                if (msg.get("pw") or "") != self.pw:
                    self._mqtt_publish_json(f"{base}/g/{cid}",
                                            {"t": "err", "msg": "房间密码错误"})
                    return
                ext = msg.get("ext")
                key = ext if ext else f"cid-{cid}"
                st = self.peers.setdefault(key, {"direct": False, "last": 0})
                st["cid"] = cid
                self.log(f"√ 玩家加入（{cid}，公网 {ext or '未知'}），开始打洞…")
                reply = {"t": "ok"}
                if self.my_ext:
                    reply["peer"] = self.my_ext
                self._mqtt_publish_json(f"{base}/g/{cid}", reply)
            elif t == "create":
                self._mqtt_publish_json(
                    f"{base}/g/{msg.get('from')}",
                    {"t": "err", "msg": "该房间已由其他房主占用"})
            elif t == "r":
                self._on_relay_msg(msg)

    def _on_relay_msg(self, msg):
        try:
            frame = base64.b64decode(msg.get("d", ""))
            parsed = parse_frame(frame)
            if parsed:
                self._on_frame(*parsed, peer=msg.get("from") or "relay",
                               via="relay")
        except Exception:
            pass

    # ---------- 数据包入口 ----------

    def on_datagram(self, data, addr):
        addr_s = f"{addr[0]}:{addr[1]}"
        if len(data) >= 20 and data[0:2] == b"\x01\x01" \
                and data[4:8] == _STUN_COOKIE:
            # STUN 应答
            if self._stun_fut:
                txid, fut = self._stun_fut
                mapped = _parse_stun_mapped(data, txid)
                if mapped and not fut.done():
                    fut.set_result(mapped)
            return
        if data[:2] == MAGIC:
            parsed = parse_frame(data)
            if parsed:
                self._on_frame(*parsed, peer=addr_s, via="direct")
            return
        try:
            msg = json.loads(data.decode("utf-8", errors="ignore"))
        except Exception:
            return
        if self.server and addr[0] == self.server[0] and addr[1] == self.server[1]:
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
        deadline = None          # 第一个对端出现后才开始计时
        while not self.stopped:
            if not self.peers:
                await asyncio.sleep(PUNCH_INTERVAL)
                continue
            if deadline is None:
                deadline = time.time() + self.punch_timeout
            direct_targets = [p for p, st in self.peers.items() if not st["direct"]]
            if direct_targets:
                frame = pack_frame(PKT_PUNCH, 0)
                for peer in direct_targets:
                    try:
                        ip, port = peer.rsplit(":", 1)
                        self.transport.sendto(frame, (ip, int(port)))
                    except Exception:
                        pass
            if all(st["direct"] for st in self.peers.values()):
                if self.role == "host":
                    self.set_status("已连接（P2P 直连），玩家可以进了")
                else:
                    self.set_status("已连接（P2P 直连）")
                return
            if time.time() > deadline:
                break
            await asyncio.sleep(PUNCH_INTERVAL)
        if self.stopped or not self.peers:
            return
        if self.sig == "manual":
            self.log("… 打洞未成功（可能双方 NAT 类型不友好）。"
                     "提示：双方都要在 30 秒内点开始；家庭宽带换双方都连手机热点常能成功")
            self.set_status("打洞未成功（手动模式无中继）")
            return
        self.use_relay = True
        self.log("… 打洞未成功（可能是对称型 NAT），自动切换中继模式兜底")
        if self.sig == "mqtt":
            self.log("  中继经公共信令服务器转发（免费共享节点，速度尽力而为）")
        self.set_status("已连接（中继模式）")

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
        targets = [peer] if peer else ([self.host_peer] if self.host_peer
                                       else list(self.peers))
        if not targets and self.sig == "mqtt" and self.role == "guest":
            targets = ["host"]        # 没有已知公网地址时也走公共信令中继
        for p in targets:
            st = self.peers.get(p)
            direct = bool(st and st["direct"])
            try:
                if direct and not self.use_relay:
                    ip, port = p.rsplit(":", 1)
                    self.transport.sendto(frame, (ip, int(port)))
                    continue
                if self.sig == "mqtt":
                    to = None
                    if self.role == "host":
                        to = (st or {}).get("cid")
                        if not to and p and ":" not in str(p):
                            to = p    # p 本身就是玩家 cid（中继流场景）
                    self._mqtt_send_frames(kind, sid, payload, frame, to)
                else:
                    msg = {"t": "r", "room": self.room,
                           "d": base64.b64encode(frame).decode()}
                    if self.role == "host" and p and p != "relay":
                        msg["to"] = p
                    self._send_json(msg)
            except Exception:
                pass

    def _mqtt_send_frames(self, kind, sid, payload, frame, to):
        """经公共信令（MQTT）中继；大 DATA 包分片（公共 broker 单包约 1MB 上限）"""
        if not self.mqtt or not self.mqtt.alive:
            return
        if self.role == "guest":
            topic = f"{self._topic_base}/host"
        else:
            if not to:
                return
            topic = f"{self._topic_base}/g/{to}"
        if kind == PKT_DATA and len(payload) > 180000:
            for i in range(0, len(payload), 180000):
                sub = pack_frame(PKT_DATA, sid, payload[i:i + 180000])
                msg = {"t": "r", "from": self.cid,
                       "d": base64.b64encode(sub).decode()}
                asyncio.create_task(self.mqtt.publish(topic, json.dumps(msg),
                                                      qos=0))
        else:
            msg = {"t": "r", "from": self.cid,
                   "d": base64.b64encode(frame).decode()}
            asyncio.create_task(self.mqtt.publish(topic, json.dumps(msg), qos=0))

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
        # 后台探测一次公网 IPv4（缓存共享给界面显示）
        threading.Thread(target=get_public_ipv4, daemon=True,
                         name="mclink-stun").start()

    def log(self, text):
        line = f"[{time.strftime('%H:%M:%S')}] {text}"
        with self._lock:
            self._logbuf.append(line)
        self._log(text)

    def set_status(self, text):
        self.status_text = text
        self.log("状态：" + text)

    def start(self, role, server, room, pw="", *, target_port=None,
              listen_port=None, udp_listen_port=None, udp_target_port=None,
              sig="udp", manual_peer=None, ext=None, punch_timeout=None):
        """启动隧道。sig: "udp"=自建信令 / "mqtt"=公共信令 / "manual"=手动IP"""
        if isinstance(server, str) and server:
            ip, port = server.rsplit(":", 1)
            server = (ip, int(port))
        elif not server:
            server = None
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
                                 udp_listen_port=ulp, udp_target_port=utp,
                                 sig=sig, manual_peer=manual_peer, ext=ext,
                                 punch_timeout=punch_timeout)
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
<div class="sub">MCLink · 我的世界 Java 版 P2P 打洞（IPv4）· 公共信令免服务器 · 电脑 &amp; FCL 手机通用</div>

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
    <div><label>信令方式</label>
      <select id="sig" onchange="sigChanged()">
        <option value="public">公共信令（推荐，免服务器）</option>
        <option value="udp">自建信令服务器</option>
        <option value="manual">手动IP（无信令）</option>
      </select></div>
  </div>
  <div id="rowServer" style="display:none">
    <label>信令服务器（IP:端口）</label>
    <input id="server" placeholder="例如 1.2.3.4:42339">
  </div>
  <div id="rowPeer" style="display:none">
    <label>房主公网地址（IP:端口，房主把「我的公网地址」发给你）</label>
    <input id="peer" placeholder="例如 111.112.113.114:54321">
  </div>
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
  <b>本机信息（局域网直连 / 分享公网地址用）</b>
  <div class="info" id="info">…</div>
  <button class="ghost" onclick="copyJoin()">复制局域网地址</button>
</div>

<div class="card"><b>日志</b><pre id="log">…</pre></div>

<script>
function sel(id){ return document.getElementById(id).value.trim(); }
function sigChanged(){
  const s = sel('sig');
  document.getElementById('rowServer').style.display = s==='udp' ? '' : 'none';
  document.getElementById('rowPeer').style.display = (s==='manual' && sel('role')==='guest') ? '' : 'none';
}
async function act(a){
  const body = {action:a, role:sel('role'), sig:sel('sig'), server:sel('server'),
                peer:sel('peer'), room:sel('room'), pw:sel('pw'),
                port:parseInt(sel('port')||'25565')};
  await fetch('/api/action', {method:'POST', headers:{'Content-Type':'application/json'},
                              body:JSON.stringify(body)});
  sigChanged();
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
      '局域网 IP：<b>'+s.info.lan_ip+'</b>（同 Wi-Fi 直连用）<br>'+
      '公网 IPv4：<b>'+s.info.public_ip+'</b>（跨网联机时用）<br>'+
      'Java 监听端口：<b>'+s.info.java_ports_text+'</b><br>'+
      'IPv6：<b>'+(s.info.ipv6||'无')+'</b>';
    document.getElementById('joinHint').textContent = '127.0.0.1:'+sel('port');
  }catch(e){}
}
setInterval(poll, 1200); poll(); sigChanged();
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
            sig = msg.get("sig", "public")
            if sig == "public":
                sig = "mqtt"
            server = msg.get("server") or DEFAULT_SERVER
            room = msg.get("room") or f"room{random.randint(1000, 9999)}"
            pw = msg.get("pw", "")
            port = int(msg.get("port") or 25565)
            manual_peer = msg.get("peer") or None
            if sig == "manual" and role == "guest" and manual_peer:
                manual_peer = manual_peer.strip()
            else:
                manual_peer = None
            sig_desc = {"mqtt": "公共信令", "udp": f"自建信令 {server}",
                        "manual": "手动IP"}[sig]
            self.app.log(f"Web 控制台操作：{'开房间' if role == 'host' else '加入'} "
                         f"方式={sig_desc} 房间={room}")
            self.app.start(role, server if sig == "udp" else None, room, pw,
                           target_port=port, listen_port=port,
                           sig=sig, manual_peer=manual_peer)
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
        c.add_argument("--sig", default="public",
                       choices=["public", "udp", "manual"],
                       help="信令方式：public=公共信令(默认) / udp=自建信令 / manual=手动IP")
        c.add_argument("--server", default=DEFAULT_SERVER, help="自建信令服务器 IP:端口")
        c.add_argument("--peer", default="", help="手动模式：房主公网地址 IP:端口")
        c.add_argument("--pw", default="", help="房间密码")
        c.add_argument("--port", type=int, default=25565,
                       help="房主=本机游戏端口 / 玩家=本地监听端口")

    args = p.parse_args()
    if args.cmd == "info":
        for k, v in network_info(include_public=True).items():
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
        sig_desc = {"public": "公共信令", "udp": f"自建信令 {args.server}",
                    "manual": "手动IP"}[args.sig]
        app = MCLinkApp()
        print(f"MCLink {('房主模式' if role == 'host' else '玩家模式')}："
              f"信令={sig_desc} 房间={args.room}")
        if role == "guest":
            print(f"启动后在 MC「直接连接」里填：127.0.0.1:{args.port}")
        app.start(role, args.server if args.sig == "udp" else None,
                  args.room, args.pw, target_port=args.port,
                  listen_port=args.port, sig=args.sig,
                  manual_peer=args.peer or None)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            app.stop()


if __name__ == "__main__":
    main()
