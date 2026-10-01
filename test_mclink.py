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


async def main():
    port_sig = 42339 + (int(time.time()) % 50)   # 随机化避免占用冲突
    port_game = 35565 + (int(time.time()) % 50)  # 房主侧"游戏"TCP端口
    port_udp_game = 45132 + (int(time.time()) % 50)
    port_listen = 45565 + (int(time.time()) % 50)  # 玩家侧本地监听
    port_udp_listen = 46132 + (int(time.time()) % 50)

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
    # host 不开监听（房主被动接收）
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

    # 5. TCP 转发测试：玩家侧连接本地监听端口 → 应到达房主侧游戏端口
    reader, writer = await asyncio.open_connection("127.0.0.1", port_listen)
    payload = b"hello-mclink-tcp-" + str(time.time()).encode()
    writer.write(payload)
    await writer.drain()
    got = await asyncio.wait_for(reader.read(4096), 10)
    assert got == payload, f"TCP 回显不一致：{got!r}"
    writer.close()
    log(f"√ TCP 转发通过（{len(payload)} 字节回显一致）")

    # 6. UDP 转发测试（注意：echo 服务器在主循环上，不能用阻塞 recvfrom 卡死循环）
    loop = asyncio.get_running_loop()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(10)
    upayload = b"udp-ping-" + str(time.time()).encode()
    u.sendto(upayload, ("127.0.0.1", port_udp_listen))
    data, _ = await asyncio.wait_for(
        asyncio.to_thread(u.recvfrom, 4096), 10)
    assert data == upayload, f"UDP 回显不一致：{data!r}"
    u.close()
    log(f"√ UDP 转发通过（{len(upayload)} 字节回显一致）")

    # 7. 多条 TCP 并发
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

    # 8. 收尾
    print("\n=== 全部测试通过 ===", flush=True)
    with open(r"D:\tmp\mclink_test_result.txt", "w", encoding="utf-8") as f:
        f.write("PASS")
    import os
    os._exit(0)   # 干脆退出：app 的常驻循环线程无需优雅回收


if __name__ == "__main__":
    core._fix_win_console()
    asyncio.run(main())
