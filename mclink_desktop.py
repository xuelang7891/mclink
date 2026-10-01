#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCLink 桌面版（电脑端图形界面）

  python mclink_desktop.py

界面功能：
  - P2P 联机（房主/玩家），Java 版 TCP 转发，打洞失败自动中继
  - 本机信息（局域网 IP / IPv6 / 自动检测 MC 局域网端口）
  - 一键启动 Web 控制台（手机浏览器可远程操作本程序）
纯标准库，无需安装任何依赖。
"""

import sys
import threading
import time
import webbrowser

import mclink_core as core

DEFAULT_SERVER = "127.0.0.1:42339"   # 改成你的公网信令服务器


def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox

    root = tk.Tk()
    root.title("薛朗的联机工具 - MCLink")
    root.geometry("640x620")
    root.minsize(560, 540)

    app = core.MCLinkApp(log=lambda s: root.after(0, lambda: push_log(s)))

    # ---------------- 顶部：状态 ----------------
    frm_status = ttk.LabelFrame(root, text="状态")
    frm_status.pack(fill="x", padx=10, pady=(10, 6))
    lbl_status = ttk.Label(frm_status, text="状态：空闲", font=("", 11, "bold"))
    lbl_status.pack(anchor="w", padx=8, pady=4)

    # ---------------- 中部：联机设置 ----------------
    frm_set = ttk.LabelFrame(root, text="P2P 联机（Java 版，电脑 & 手机 FCL 通用）")
    frm_set.pack(fill="x", padx=10, pady=6)

    grid = ttk.Frame(frm_set)
    grid.pack(fill="x", padx=8, pady=6)
    grid.columnconfigure(1, weight=1)

    ttk.Label(grid, text="我的角色：").grid(row=0, column=0, sticky="w")
    role_var = tk.StringVar(value="host")
    frm_role = ttk.Frame(grid)
    frm_role.grid(row=0, column=1, sticky="w")
    ttk.Radiobutton(frm_role, text="房主（我开世界）", value="host",
                    variable=role_var).pack(side="left")
    ttk.Radiobutton(frm_role, text="玩家（我加入）", value="guest",
                    variable=role_var).pack(side="left", padx=12)

    ttk.Label(grid, text="信令方式：").grid(row=1, column=0, sticky="w")
    sig_var = tk.StringVar(value="public")
    frm_sig = ttk.Frame(grid)
    frm_sig.grid(row=1, column=1, sticky="w")
    rb_public = ttk.Radiobutton(frm_sig, text="公共信令（推荐）", value="public",
                                variable=sig_var)
    rb_udp = ttk.Radiobutton(frm_sig, text="自建服务器", value="udp",
                             variable=sig_var)
    rb_manual = ttk.Radiobutton(frm_sig, text="手动IP", value="manual",
                                variable=sig_var)
    rb_public.pack(side="left")
    rb_udp.pack(side="left", padx=8)
    rb_manual.pack(side="left")

    lbl_server_title = ttk.Label(grid, text="信令服务器：")
    lbl_server_title.grid(row=2, column=0, sticky="w")
    ent_server = ttk.Entry(grid)
    ent_server.insert(0, DEFAULT_SERVER)
    ent_server.grid(row=2, column=1, sticky="ew", pady=2)
    lbl_peer_title = ttk.Label(grid, text="房主公网地址：")
    ent_peer = ttk.Entry(grid)
    ttk.Label(grid, text="房间号：").grid(row=3, column=0, sticky="w")
    ent_room = ttk.Entry(grid)
    ent_room.insert(0, "")
    ent_room.grid(row=3, column=1, sticky="ew", pady=2)
    ttk.Label(grid, text="密码（可空）：").grid(row=4, column=0, sticky="w")
    ent_pw = ttk.Entry(grid)
    ent_pw.grid(row=4, column=1, sticky="ew", pady=2)
    ttk.Label(grid, text="游戏端口：").grid(row=5, column=0, sticky="w")
    ent_port = ttk.Entry(grid, width=10)
    ent_port.insert(0, "25565")
    ent_port.grid(row=5, column=1, sticky="w", pady=2)
    lbl_port_tip = ttk.Label(grid, text="房主：MC 局域网开放时显示的端口；玩家：保持默认即可",
                             foreground="#888")
    lbl_port_tip.grid(row=6, column=1, sticky="w")

    def update_sig_rows(*_):
        s = sig_var.get()
        for w in (lbl_server_title, ent_server):
            if s == "udp":
                lbl_server_title.grid(row=2, column=0, sticky="w")
                ent_server.grid(row=2, column=1, sticky="ew", pady=2)
            else:
                ent_server.grid_remove()
                lbl_server_title.grid_remove()
        if s == "manual":
            lbl_peer_title.grid(row=2, column=0, sticky="w")
            ent_peer.grid(row=2, column=1, sticky="ew", pady=2)
        else:
            ent_peer.grid_remove()
            lbl_peer_title.grid_remove()
    for rb in (rb_public, rb_udp, rb_manual):
        rb.configure(command=update_sig_rows)
    update_sig_rows()

    frm_btn = ttk.Frame(frm_set)
    frm_btn.pack(fill="x", padx=8, pady=(0, 8))
    btn_start = ttk.Button(frm_btn, text="开始联机")
    btn_start.pack(side="left")
    btn_stop = ttk.Button(frm_btn, text="停止", state="disabled", command=app.stop)
    btn_stop.pack(side="left", padx=8)

    # ---------------- 信息区 ----------------
    frm_info = ttk.LabelFrame(root, text="本机信息（局域网直连 / IPv6 直连用）")
    frm_info.pack(fill="x", padx=10, pady=6)
    lbl_info = ttk.Label(frm_info, text="（点击「刷新信息」检测）", justify="left")
    lbl_info.pack(anchor="w", padx=8, pady=4)

    frm_info_btn = ttk.Frame(frm_info)
    frm_info_btn.pack(fill="x", padx=8, pady=(0, 6))
    btn_refresh = ttk.Button(frm_info_btn, text="刷新信息")
    btn_refresh.pack(side="left")
    btn_copy = ttk.Button(frm_info_btn, text="复制联机地址")
    btn_copy.pack(side="left", padx=8)
    btn_web = ttk.Button(frm_info_btn, text="启动手机控制台(Web)")
    btn_web.pack(side="left")

    # ---------------- 日志 ----------------
    frm_log = ttk.LabelFrame(root, text="日志")
    frm_log.pack(fill="both", expand=True, padx=10, pady=6)
    txt = tk.Text(frm_log, height=10, state="disabled", wrap="word",
                  font=("Consolas", 9))
    txt.pack(fill="both", expand=True, padx=4, pady=4)

    # ---------------- 逻辑 ----------------

    def push_log(s):
        txt.configure(state="normal")
        txt.insert("end", f"[{time.strftime('%H:%M:%S')}] {s}\n")
        txt.see("end")
        txt.configure(state="disabled")

    def refresh_status():
        lbl_status.configure(text="状态：" + app.status_text)
        root.after(800, refresh_status)

    def do_start():
        server = ent_server.get().strip()
        room = ent_room.get().strip()
        try:
            port = int(ent_port.get().strip() or "25565")
        except ValueError:
            messagebox.showerror("MCLink", "端口必须是数字")
            return
        if not room:
            messagebox.showerror("MCLink", "请填写房间号（随便起一个，和朋友约好同一个即可）")
            return
        role = role_var.get()
        sig = sig_var.get()
        manual_peer = None
        if sig == "manual":
            if role == "guest":
                manual_peer = ent_peer.get().strip()
                if not manual_peer:
                    messagebox.showerror("MCLink", "手动IP模式：玩家需要填房主公网地址")
                    return
        app.start(role, server if sig == "udp" else None, room,
                  ent_pw.get().strip(),
                  target_port=port, listen_port=port,
                  sig=sig, manual_peer=manual_peer)
        btn_start.configure(state="disabled")
        btn_stop.configure(state="normal")
        if role == "guest":
            push_log(f"提示：在 MC 多人游戏「直接连接」里填 127.0.0.1:{port}")

    def do_stop():
        app.stop()
        btn_start.configure(state="normal")
        btn_stop.configure(state="disabled")

    btn_start.configure(command=do_start)

    def do_refresh():
        info = core.network_info(include_public=True)
        lbl_info.configure(text=(
            f"局域网 IP：{info['lan_ip']}\n"
            f"公网 IPv4：{info['public_ip']}\n"
            f"Java 监听端口：{info['java_ports_text']}\n"
            f"IPv6：{info['ipv6']}\n"
            f"说明：同一 Wi-Fi 下，朋友在 MC「直接连接」填 局域网IP:端口；\n"
            f"          否则用上面的 P2P 联机（IPv4 打洞，失败自动中继）"))
        push_log("已刷新本机信息")

    btn_refresh.configure(command=do_refresh)

    def do_copy():
        info = core.network_info()
        addr = f"{info['lan_ip']}:{ent_port.get().strip() or 25565}"
        root.clipboard_clear()
        root.clipboard_append(addr)
        push_log(f"已复制联机地址：{addr}")

    btn_copy.configure(command=do_copy)

    def do_web():
        httpd, port = core.start_web_console(app, 8765)
        ip = core.get_local_ipv4()
        push_log(f"Web 控制台已启动：手机浏览器打开 http://{ip}:{port}")
        messagebox.showinfo(
            "手机控制台已启动",
            f"手机和电脑连同一个 Wi-Fi，\n用浏览器打开：\n\nhttp://{ip}:{port}\n\n"
            f"即可在手机上操作本工具")
        webbrowser.open(f"http://127.0.0.1:{port}")

    btn_web.configure(command=do_web)

    refresh_status()
    push_log("MCLink 已启动。房主先在 MC 里对局域网开放世界，再点「开始联机」。")
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()


if __name__ == "__main__":
    core._fix_win_console()
    run_gui()
