#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCLink 端到端自测：
  信令服务器 + 房主端 + 玩家端 全部在本机启动，
  房主侧模拟游戏服务器（TCP echo + UDP echo），
  玩家侧通过隧道连接，验证 TCP / UDP 双向转发。

  python test_mclink.py
"""

import asyncio
import socket
import sys
import time

sys.path.insert(0, ".")

import mclink_core as core
import mclink_server as srv


def log(msg):
    print(f"[test {time.strftime('%H:%M:%S')}] {msg}", flush=True)


async def echo_tcp_server(port):
    async def handle(r, w):
        try:
            while True:
                data = await r.read(4096)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except Exception:
            pass
        finally:
            w.close()
    server = await asyncio.start_server(handle, "127.0.0.1", port)
    return server


async def echo_udp_server(port):
    class P(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.t = transport

        def datagram_received(self, data, addr):
            self.t.sendto(data, addr)
    loop = asyncio.get_running_loop()
    return await loop.create_datagram_endpoint(P, local_addr=("127.0.0.1", port))


async def wait_status(app, keyword, timeout=25):
    """异步等待状态（不能阻塞事件循环，否则信令服务器收不到包）"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = app.status_text
        if keyword in s:
            return s
        await asyncio.sleep(0.3)
    raise AssertionError(f"等待状态「{keyword}」超时，当前状态：{app.status_text}\n日志：\n" +
                         "\n".join(app.snapshot()["log"]))


async def tcp_roundtrip(port_listen, label, timeout=15):
    """一条 TCP 连接走完隧道并回显"""
    reader, writer = await asyncio.open_connection("127.0.0.1", port_listen)
    payload = b"hello-mclink-tcp-" + label.encode() + b"-" + str(time.time()).encode()
    writer.write(payload)
    await writer.drain()
    got = await asyncio.wait_for(reader.read(65536), timeout)
    assert got == payload, f"TCP 回显不一致：{got!r}"
    writer.close()
    log(f"√ TCP 转发通过（{label}，{len(payload)} 字节回显一致）")


async def udp_roundtrip(port_udp_listen, timeout=15):
    """UDP 数据包走完隧道并回显（收包放线程，避免卡死事件循环）"""
    loop = asyncio.get_running_loop()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(timeout)
    upayload = b"udp-ping-" + str(time.time()).encode()
    u.sendto(upayload, ("127.0.0.1", port_udp_listen))
    data, _ = await asyncio.wait_for(
        asyncio.to_thread(u.recvfrom, 4096), timeout)
    assert data == upayload, f"UDP 回显不一致：{data!r}"
    u.close()
    log(f"√ UDP 转发通过（{len(upayload)} 字节回显一致）")


async def run_udp_test(port_sig, port_game, port_udp_game, port_listen,
                       port_udp_listen):
    """原 v1.0 测试：本机自建信令服务器 + P2P 打洞直连"""
    # 1. 启动信令服务器
    server = srv.Server(port_sig)
    task = asyncio.create_task(server.run())
    await asyncio.sleep(0.5)
    log(f"信令服务器已启动 127.0.0.1:{port_sig}")

    # 2. 房主侧模拟游戏服务器
    tcp_srv = await echo_tcp_server(port_game)
    udp_srv = await echo_udp_server(port_udp_game)
    log(f"模拟游戏服务器：TCP {port_game} / UDP {port_udp_game}")

    # 3. 房主客户端
    host_app = core.MCLinkApp(log=log)
    host_app.start("host", f"127.0.0.1:{port_sig}", "testroom", "",
                   target_port=port_game, udp_target_port=port_udp_game)
    await wait_status(host_app, "等待玩家加入")
    log("房主就绪，等待玩家")

    # 4. 玩家客户端
    guest_app = core.MCLinkApp(log=log)
    guest_app.start("guest", f"127.0.0.1:{port_sig}", "testroom", "",
                    listen_port=port_listen, udp_listen_port=port_udp_listen)
    await wait_status(guest_app, "已连接")
    await wait_status(host_app, "已连接")
    log("两端隧道已建立")

    await asyncio.sleep(0.5)

    # 5. TCP / UDP 转发测试
    await tcp_roundtrip(port_listen, "udp-sig")
    await udp_roundtrip(port_udp_listen)

    # 6. 多条 TCP 并发
    async def one_conn(i):
        r, w = await asyncio.open_connection("127.0.0.1", port_listen)
        msg = f"conn-{i}-".encode() + str(time.time()).encode()
        w.write(msg)
        await w.drain()
        got = await asyncio.wait_for(r.read(4096), 10)
        assert got == msg
        w.close()
    await asyncio.gather(*(one_conn(i) for i in range(5)))
    log("√ 5 条并发 TCP 连接全部通过")

    guest_app.stop()
    host_app.stop()
    tcp_srv.close()
    udp_srv[0].close()
    task.cancel()
    return "PASS-UDP"


async def run_mqtt_direct_test():
    """公共信令（MQTT，真实公网 broker）+ P2P 打洞。
    ext="auto" 让两端把回环地址当公网映射，验证真实信令 + 完整打洞链路。"""
    room = f"mctest{int(time.time() * 10) % 100000000}"
    port_game = 36565 + (int(time.time()) % 50)
    port_listen = 37565 + (int(time.time()) % 50)
    tcp_srv = await echo_tcp_server(port_game)
    log(f"[MQTT-直连] 房间={room}（连真实公共 broker）")

    host_app = core.MCLinkApp(log=log)
    host_app.start("host", None, room, "", target_port=port_game,
                   sig="mqtt", ext="auto")
    await wait_status(host_app, "等待玩家加入", 40)
    log("房主经公共信令就绪")

    guest_app = core.MCLinkApp(log=log)
    guest_app.start("guest", None, room, "", listen_port=port_listen,
                    sig="mqtt", ext="auto")
    await wait_status(guest_app, "P2P 直连", 40)
    await wait_status(host_app, "P2P 直连", 10)
    log("公共信令 + 打洞直连建立成功")

    await tcp_roundtrip(port_listen, "mqtt-direct")
    guest_app.stop()
    host_app.stop()
    tcp_srv.close()
    return "PASS-MQTT-DIRECT"


async def run_mqtt_relay_test():
    """公共信令中继兜底：故意给两端错误的公网映射，逼打洞失败走中继。"""
    room = f"mcrelay{int(time.time() * 10) % 100000000}"
    port_game = 38565 + (int(time.time()) % 50)
    port_listen = 39565 + (int(time.time()) % 50)
    tcp_srv = await echo_tcp_server(port_game)
    log(f"[MQTT-中继] 房间={room}（打洞必败 → 公共 broker 中继）")

    host_app = core.MCLinkApp(log=log)
    host_app.start("host", None, room, "", target_port=port_game,
                   sig="mqtt", ext="127.0.0.1:1", punch_timeout=3)
    await wait_status(host_app, "等待玩家加入", 40)

    guest_app = core.MCLinkApp(log=log)
    guest_app.start("guest", None, room, "", listen_port=port_listen,
                    sig="mqtt", ext="127.0.0.1:1", punch_timeout=3)
    await wait_status(guest_app, "中继模式", 45)
    await wait_status(host_app, "中继模式", 10)
    log("自动切换中继成功（数据经公共信令服务器转发）")

    await tcp_roundtrip(port_listen, "mqtt-relay", timeout=30)
    guest_app.stop()
    host_app.stop()
    tcp_srv.close()
    return "PASS-MQTT-RELAY"


async def main():
    """单测入口：python test_mclink.py [udp|mqtt-direct|mqtt-relay]"""
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    base = int(time.time())
    if mode == "udp":
        r = await run_udp_test(
            port_sig=42339 + base % 50, port_game=35565 + base % 50,
            port_udp_game=45132 + base % 50, port_listen=45565 + base % 50,
            port_udp_listen=46132 + base % 50)
    elif mode == "mqtt-direct":
        r = await run_mqtt_direct_test()
    elif mode == "mqtt-relay":
        r = await run_mqtt_relay_test()
    else:
        await run_all()
        return
    print(f"=== {mode} 测试通过：{r} ===", flush=True)
    with open(r"D:\tmp\mclink_test_result.txt", "a", encoding="utf-8") as f:
        f.write(r + " ")
    import os
    os._exit(0)   # 干脆退出：app 的常驻循环线程无需优雅回收


async def run_all():
    """依次以子进程隔离运行三个测试，汇总结果"""
    import subprocess
    py = sys.executable
    script = __file__
    results = []
    for mode in ("udp", "mqtt-direct", "mqtt-relay"):
        log(f"===== 子测试：{mode} =====")
        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                [py, "-u", script, mode],
                capture_output=True, text=True, timeout=150,
                errors="replace")
            out = (proc.stdout or "") + (proc.stderr or "")
            print(out[-1500:], flush=True)
            if proc.returncode == 0:
                results.append(mode)
            else:
                log(f"× {mode} 失败（exit={proc.returncode}）")
        except subprocess.TimeoutExpired:
            log(f"× {mode} 超时")
    print("\n=== 汇总：" + (" / ".join(results) if results else "无") +
          " ===", flush=True)
    with open(r"D:\tmp\mclink_test_result.txt", "w", encoding="utf-8") as f:
        f.write(" ".join(results))
    import os
    os._exit(0)


if __name__ == "__main__":
    core._fix_win_console()
    asyncio.run(main())
