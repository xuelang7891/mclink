#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
薛朗的联机工具 —— 双击入口（exe 用）

双击后：启动本地联机服务 + 自动打开浏览器控制台。
所有操作（房主/玩家/信令方式/端口）都在网页上完成，电脑手机通用。
"""

import sys
import time
import webbrowser

import mclink_core as core


def main():
    core._fix_win_console()
    app = core.MCLinkApp(log=lambda s: None)   # exe 窗口模式下静默日志
    port = None
    for p in (8765, 8766, 18765, 28765, 0):
        try:
            _, real = core.start_web_console(app, p)
            port = real
            break
        except OSError:
            continue
    if port is None:
        return
    webbrowser.open(f"http://127.0.0.1:{port}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        app.stop()


if __name__ == "__main__":
    main()
