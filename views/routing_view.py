"""
Aba 3: Central de VPN, Servidor Proxy SOCKS5 Local, Pool de Rotação de Proxies e Auditoria DNS.
Subdividida em 3 sub-painéis táticos:
  1. Gerenciador de VPN & Adaptadores TUN/TAP (WireGuard, OpenVPN, Rasdial/nmcli, Leak Check).
  2. Servidor Proxy SOCKS5 Local (RFC 1928) + Pool & Rotação de Proxies Externos (Health-Check).
  3. Teste de Rota HTTP/HTTPS Customizada & Inspetor DNS (A, AAAA, PTR).
"""

import base64
import concurrent.futures
import datetime
import json
import os
import secrets
import select
import socket
import struct
import threading
import time
from tkinter import filedialog
from typing import List, Tuple
import customtkinter as ctk
import requests
from core.theme import TacticalTheme
from core.system_platform import SystemPlatform


class RoutingView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=TacticalTheme.BG_PANEL, corner_radius=10, **kwargs)
        self.socks_server_running = False
        self.socks_server_sock = None
        self.socks_active_clients = 0
        self.working_proxies: List[Tuple[str, float]] = []
        self.current_proxy_index = 0
        self.selected_vpn_config_path = ""
        self._build_ui()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Cabeçalho Principal
        header = ctk.CTkFrame(self, fg_color=TacticalTheme.BG_CARD, corner_radius=8)
        header.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 6))
        ctk.CTkLabel(
            header,
            text="[03] CENTRAL DE VPN, SERVIDOR PROXY SOCKS5 & ROTEAMENTO DINÂMICO",
            font=TacticalTheme.font(14, "bold"),
            text_color=TacticalTheme.ACCENT_CYAN,
        ).pack(anchor="w", padx=14, pady=(10, 2))
        ctk.CTkLabel(
            header,
            text="Gerenciamento de interfaces VPN (WireGuard/OpenVPN/TUN-TAP), Servidor SOCKS5 integrado, Pool de Rotação de Proxies e Leak Test.",
            font=TacticalTheme.font(11),
            text_color=TacticalTheme.TEXT_SECONDARY,
        ).pack(anchor="w", padx=14, pady=(0, 10))

        # Abas Internas (Sub-módulos de VPN & Proxy)
        self.tabview = ctk.CTkTabview(
            self,
            fg_color=TacticalTheme.BG_CARD,
            segmented_button_fg_color=TacticalTheme.BG_SIDEBAR,
            segmented_button_selected_color=TacticalTheme.ACCENT_CYAN,
            segmented_button_selected_hover_color=TacticalTheme.ACCENT_CYAN_HOVER,
            segmented_button_unselected_color=TacticalTheme.BG_INPUT,
            text_color="#000000",
            corner_radius=8,
        )
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=14, pady=(2, 14))

        self.tab_vpn = self.tabview.add("🛡️ VPN & Adaptadores TUN/TAP")
        self.tab_proxy = self.tabview.add("🌐 Servidor Proxy SOCKS5 & Pool")
        self.tab_http_dns = self.tabview.add("🔍 Auditoria HTTP & DNS")

        self._build_vpn_tab()
        self._build_proxy_tab()
        self._build_http_dns_tab()

    # =========================================================================
    # SUB-ABA 1: GERENCIADOR DE VPN & ADAPTADORES TUN/TAP
    # =========================================================================
    def _build_vpn_tab(self) -> None:
        self.tab_vpn.grid_columnconfigure(0, weight=1)
        self.tab_vpn.grid_columnconfigure(1, weight=1)
        self.tab_vpn.grid_rowconfigure(1, weight=1)

        # Card Esquerdo: Controle de Perfil VPN & Gerador WireGuard
        vpn_ctrl = ctk.CTkFrame(
            self.tab_vpn,
            fg_color=TacticalTheme.BG_PANEL,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        vpn_ctrl.grid(row=0, column=0, sticky="nsew", padx=(8, 4), pady=8)
        vpn_ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            vpn_ctrl,
            text="CONECTOR DE PERFIS VPN (OPENVPN / WIREGUARD / RAS)",
            font=TacticalTheme.font(12, "bold"),
            text_color=TacticalTheme.ACCENT_GREEN,
        ).grid(row=0, column=0, columnspan=3, sticky="w", padx=12, pady=(10, 6))

        ctk.CTkLabel(vpn_ctrl, text="Arquivo (.ovpn / .conf):", font=TacticalTheme.font(11)).grid(
            row=1, column=0, sticky="w", padx=12, pady=4
        )
        self.entry_vpn_file = ctk.CTkEntry(
            vpn_ctrl,
            fg_color=TacticalTheme.BG_INPUT,
            font=TacticalTheme.font(11),
            placeholder_text="Selecione um perfil .ovpn ou .conf...",
        )
        self.entry_vpn_file.grid(row=1, column=1, sticky="ew", padx=6, pady=4)

        ctk.CTkButton(
            vpn_ctrl,
            text="Importar...",
            width=90,
            font=TacticalTheme.font(11),
            fg_color=TacticalTheme.BG_INPUT,
            hover_color=TacticalTheme.ACCENT_DARK_BORDER,
            command=self._select_vpn_file,
        ).grid(row=1, column=2, padx=(4, 12), pady=4)

        ctk.CTkLabel(vpn_ctrl, text="Perfil do SO (Rasdial/nmcli):", font=TacticalTheme.font(11)).grid(
            row=2, column=0, sticky="w", padx=12, pady=4
        )
        self.entry_vpn_profile = ctk.CTkEntry(
            vpn_ctrl,
            fg_color=TacticalTheme.BG_INPUT,
            font=TacticalTheme.font(11),
            placeholder_text="Nome da conexão VPN do sistema (opcional)",
        )
        self.entry_vpn_profile.grid(row=2, column=1, columnspan=2, sticky="ew", padx=(6, 12), pady=4)

        btn_vpn_row = ctk.CTkFrame(vpn_ctrl, fg_color="transparent")
        btn_vpn_row.grid(row=3, column=0, columnspan=3, sticky="ew", padx=12, pady=(8, 10))
        btn_vpn_row.grid_columnconfigure((0, 1, 2), weight=1)

        ctk.CTkButton(
            btn_vpn_row,
            text="CONECTAR VPN",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_GREEN,
            hover_color=TacticalTheme.ACCENT_GREEN_HOVER,
            text_color="#000000",
            command=self._connect_vpn,
        ).grid(row=0, column=0, padx=3, sticky="ew")

        ctk.CTkButton(
            btn_vpn_row,
            text="DESCONECTAR",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_RED,
            hover_color="#c92a42",
            text_color="#ffffff",
            command=self._disconnect_vpn,
        ).grid(row=0, column=1, padx=3, sticky="ew")

        ctk.CTkButton(
            btn_vpn_row,
            text="GERAR WIREGUARD (.CONF)",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_CYAN,
            hover_color=TacticalTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            command=self._generate_wireguard_template,
        ).grid(row=0, column=2, padx=3, sticky="ew")

        # Card Direito: Auditoria de Vazamento de VPN (IP / ISP / DNS Leak Check)
        leak_card = ctk.CTkFrame(
            self.tab_vpn,
            fg_color=TacticalTheme.BG_PANEL,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        leak_card.grid(row=0, column=1, sticky="nsew", padx=(4, 8), pady=8)
        leak_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            leak_card,
            text="AUDITORIA DE TÚNEL VPN & DETECTOR DE VAZAMENTO (IP/DNS)",
            font=TacticalTheme.font(12, "bold"),
            text_color=TacticalTheme.ACCENT_CYAN,
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        self.lbl_vpn_status = ctk.CTkLabel(
            leak_card,
            text="Status de Túnel: Aguardando verificação...",
            font=TacticalTheme.font(11, "bold"),
            text_color=TacticalTheme.ACCENT_AMBER,
        )
        self.lbl_vpn_status.grid(row=1, column=0, sticky="w", padx=12, pady=2)

        self.lbl_public_ip = ctk.CTkLabel(
            leak_card,
            text="IP Público: - | ISP/ASN: - | Local: -",
            font=TacticalTheme.font(11),
            text_color=TacticalTheme.TEXT_PRIMARY,
        )
        self.lbl_public_ip.grid(row=2, column=0, sticky="w", padx=12, pady=2)

        btn_audit_row = ctk.CTkFrame(leak_card, fg_color="transparent")
        btn_audit_row.grid(row=3, column=0, sticky="ew", padx=12, pady=(8, 10))
        btn_audit_row.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkButton(
            btn_audit_row,
            text="ATUALIZAR INTERFACES TUN/TAP",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.BG_INPUT,
            hover_color=TacticalTheme.ACCENT_DARK_BORDER,
            command=self._refresh_vpn_interfaces,
        ).grid(row=0, column=0, padx=3, sticky="ew")

        self.btn_leak_check = ctk.CTkButton(
            btn_audit_row,
            text="EXECUTAR TESTE DE VAZAMENTO (IP/DNS)",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_CYAN,
            hover_color=TacticalTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            command=self._run_vpn_leak_test,
        )
        self.btn_leak_check.grid(row=0, column=1, padx=3, sticky="ew")

        # Console de Interfaces VPN & Logs de Túnel
        self.txt_vpn_log = ctk.CTkTextbox(
            self.tab_vpn,
            fg_color=TacticalTheme.BG_TERMINAL,
            text_color=TacticalTheme.ACCENT_GREEN,
            font=TacticalTheme.font(11),
        )
        self.txt_vpn_log.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=8, pady=(0, 8))
        self._refresh_vpn_interfaces()

    def _vpn_log(self, msg: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.txt_vpn_log.insert("end", f"[{ts}] {msg}\n")
        self.txt_vpn_log.see("end")

    def _refresh_vpn_interfaces(self) -> None:
        ifaces = SystemPlatform.inspect_network_interfaces()
        vpn_active_count = sum(
            1 for i in ifaces if i["is_vpn"] == "1" and "UP" in i["status"]
        )
        if vpn_active_count > 0:
            self.lbl_vpn_status.configure(
                text=f"Status de Túnel: {vpn_active_count} Interface(s) VPN/TUN Ativa(s) Detectada(s)",
                text_color=TacticalTheme.ACCENT_GREEN,
            )
        else:
            self.lbl_vpn_status.configure(
                text="Status de Túnel: Nenhuma interface TUN/TAP/WireGuard ativa no momento",
                text_color=TacticalTheme.ACCENT_AMBER,
            )

        lines = [
            "=== MAPEAMENTO DE ADAPTADORES DE REDE & INTERFACES VPN (TUN/TAP/WIREGUARD) ===",
            f"{'INTERFACE':<28} | {'CLASSIFICAÇÃO':<16} | {'STATUS':<11} | {'ENDEREÇO IPv4':<16} | {'MTU':<6} | {'VELOCIDADE'}",
            "-" * 100,
        ]
        for item in ifaces:
            lines.append(
                f"{item['name'][:28]:<28} | {item['type']:<16} | {item['status']:<11} | {item['ipv4']:<16} | {item['mtu']:<6} | {item['speed']}"
            )
        lines.append("-" * 100)
        self.txt_vpn_log.delete("1.0", "end")
        self.txt_vpn_log.insert("1.0", "\n".join(lines) + "\n")

    def _select_vpn_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Selecionar Perfil VPN (.ovpn ou .conf)",
            filetypes=[("Arquivos VPN", "*.ovpn *.conf"), ("Todos os arquivos", "*.*")],
        )
        if path:
            self.selected_vpn_config_path = path
            self.entry_vpn_file.delete(0, "end")
            self.entry_vpn_file.insert(0, path)
            self._vpn_log(f"[PERFIL CARREGADO] Arquivo selecionado: {path}")

    def _connect_vpn(self) -> None:
        cfg_path = self.entry_vpn_file.get().strip()
        profile_name = self.entry_vpn_profile.get().strip()

        if cfg_path and os.path.isfile(cfg_path):
            ext = os.path.splitext(cfg_path)[1].lower()
            if ext == ".ovpn":
                cmd = ["openvpn", "--config", cfg_path]
            elif ext == ".conf":
                if SystemPlatform.IS_WINDOWS:
                    cmd = ["wireguard", "/installtunnelservice", cfg_path]
                else:
                    cmd = ["wg-quick", "up", cfg_path]
            else:
                self._vpn_log("[AVISO] Extensão não reconhecida. Use .ovpn (OpenVPN) ou .conf (WireGuard).")
                return
            self._vpn_log(f"[VPN] Iniciando cliente nativo: {' '.join(cmd)}")
            threading.Thread(target=self._run_vpn_cmd, args=(cmd,), daemon=True).start()
        elif profile_name:
            if SystemPlatform.IS_WINDOWS:
                cmd = ["rasdial", profile_name]
            else:
                cmd = ["nmcli", "connection", "up", profile_name]
            self._vpn_log(f"[VPN DO SISTEMA] Conectando perfil '{profile_name}' via {' '.join(cmd)}...")
            threading.Thread(target=self._run_vpn_cmd, args=(cmd,), daemon=True).start()
        else:
            self._vpn_log(
                "[INSTRUÇÃO] Selecione um arquivo .ovpn/.conf ou informe o nome de um perfil VPN configurado no sistema."
            )

    def _disconnect_vpn(self) -> None:
        profile_name = self.entry_vpn_profile.get().strip()
        if SystemPlatform.IS_WINDOWS:
            cmd = ["rasdial", profile_name, "/disconnect"] if profile_name else ["rasdial", "/disconnect"]
        else:
            cmd = ["nmcli", "connection", "down", profile_name] if profile_name else ["killall", "openvpn"]
        self._vpn_log(f"[VPN] Executando desconexão: {' '.join(cmd)}")
        threading.Thread(target=self._run_vpn_cmd, args=(cmd,), daemon=True).start()

    def _run_vpn_cmd(self, cmd: List[str]) -> None:
        code, out = SystemPlatform.run_native_command(cmd, timeout=15)
        self.after(0, lambda: self._vpn_log(f"[SAÍDA VPN (código {code})]: {out}"))
        self.after(500, self._refresh_vpn_interfaces)

    def _generate_wireguard_template(self) -> None:
        priv_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        psk_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        wg_conf = (
            "# === PERFIL WIREGUARD DE LABORATÓRIO GERADO PELO NETPULSE ===\n"
            "[Interface]\n"
            f"PrivateKey = {priv_key}\n"
            "Address = 10.66.66.2/32\n"
            "DNS = 1.1.1.1, 1.0.0.1\n"
            "MTU = 1420\n\n"
            "[Peer]\n"
            "PublicKey = INSIRA_A_CHAVE_PUBLICA_DO_SERVIDOR_WIREGUARD_AQUI=\n"
            f"PresharedKey = {psk_key}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "Endpoint = vpn.laboratorio.exemplo.com:51820\n"
            "PersistentKeepalive = 25\n"
        )
        self._vpn_log("Perfil WireGuard (.conf) gerado com chaves CSPRNG de 256 bits:\n" + wg_conf)

    def _run_vpn_leak_test(self) -> None:
        self.btn_leak_check.configure(state="disabled")
        self._vpn_log("[AUDITORIA DE VAZAMENTO] Consultando IP Público, ASN/ISP e Servidores DNS do Sistema...")
        threading.Thread(target=self._leak_worker, daemon=True).start()

    def _leak_worker(self) -> None:
        dns_list = SystemPlatform.get_system_dns_servers()
        try:
            resp = requests.get("https://ipinfo.io/json", timeout=7)
            data = resp.json()
            ip = data.get("ip", "-")
            org = data.get("org", "-")
            city = data.get("city", "-")
            country = data.get("country", "-")
            loc_str = f"{city}/{country}"

            self.after(
                0,
                lambda: self.lbl_public_ip.configure(
                    text=f"IP Público: {ip} | ISP: {org[:32]} | Local: {loc_str}"
                ),
            )
            self.after(
                0,
                lambda: self._vpn_log(
                    f"[RESULTADO LEAK TEST]\n"
                    f"  -> IP de Saída Público : {ip}\n"
                    f"  -> Provedor / ASN      : {org}\n"
                    f"  -> Geolocalização      : {city} - {country} ({data.get('loc', '-')})\n"
                    f"  -> Servidores DNS SO   : {', '.join(dns_list)}"
                ),
            )
        except Exception as exc:
            self.after(0, lambda e=exc: self._vpn_log(f"[ERRO LEAK TEST] {e}"))
        finally:
            self.after(0, lambda: self.btn_leak_check.configure(state="normal"))

    # =========================================================================
    # SUB-ABA 2: SERVIDOR PROXY SOCKS5 LOCAL & POOL DE ROTAÇÃO DE PROXIES
    # =========================================================================
    def _build_proxy_tab(self) -> None:
        self.tab_proxy.grid_columnconfigure(0, weight=1)
        self.tab_proxy.grid_columnconfigure(1, weight=1)
        self.tab_proxy.grid_rowconfigure(1, weight=1)

        # Card Esquerdo: Servidor Proxy SOCKS5 Local Nativo
        srv_card = ctk.CTkFrame(
            self.tab_proxy,
            fg_color=TacticalTheme.BG_PANEL,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        srv_card.grid(row=0, column=0, sticky="nsew", padx=(8, 4), pady=8)
        srv_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            srv_card,
            text="SERVIDOR PROXY SOCKS5 LOCAL INTEGRADO (RFC 1928)",
            font=TacticalTheme.font(12, "bold"),
            text_color=TacticalTheme.ACCENT_GREEN,
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))

        ctk.CTkLabel(srv_card, text="Bind do Servidor SOCKS5:", font=TacticalTheme.font(11)).grid(
            row=1, column=0, sticky="w", padx=12, pady=4
        )
        self.entry_socks_bind = ctk.CTkEntry(srv_card, fg_color=TacticalTheme.BG_INPUT, font=TacticalTheme.font(11))
        self.entry_socks_bind.insert(0, "127.0.0.1:1080")
        self.entry_socks_bind.grid(row=1, column=1, sticky="ew", padx=12, pady=4)

        self.switch_socks_srv = ctk.CTkSwitch(
            srv_card,
            text="Ativar Servidor Proxy SOCKS5 Local",
            font=TacticalTheme.font(11, "bold"),
            progress_color=TacticalTheme.ACCENT_GREEN,
            command=self._toggle_socks5_server,
        )
        self.switch_socks_srv.grid(row=2, column=0, columnspan=2, sticky="w", padx=12, pady=(8, 4))

        self.lbl_socks_stats = ctk.CTkLabel(
            srv_card,
            text="Status: Parado | Clientes Ativos: 0",
            font=TacticalTheme.font(11),
            text_color=TacticalTheme.ACCENT_AMBER,
        )
        self.lbl_socks_stats.grid(row=3, column=0, columnspan=2, sticky="w", padx=12, pady=(2, 10))

        # Card Direito: Pool & Rotação de Proxies (Health-Checker)
        pool_card = ctk.CTkFrame(
            self.tab_proxy,
            fg_color=TacticalTheme.BG_PANEL,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        pool_card.grid(row=0, column=1, sticky="nsew", padx=(4, 8), pady=8)
        pool_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            pool_card,
            text="POOL DE PROXIES & ROTAÇÃO DINÂMICA (CHECKER)",
            font=TacticalTheme.font(12, "bold"),
            text_color=TacticalTheme.ACCENT_CYAN,
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        self.txt_proxy_pool = ctk.CTkTextbox(
            pool_card,
            fg_color=TacticalTheme.BG_INPUT,
            text_color=TacticalTheme.TEXT_PRIMARY,
            font=TacticalTheme.font(10),
            height=74,
        )
        self.txt_proxy_pool.grid(row=1, column=0, sticky="ew", padx=12, pady=4)
        self.txt_proxy_pool.insert(
            "1.0",
            "127.0.0.1:1080\n127.0.0.1:8080\n127.0.0.1:8888",
        )

        btn_pool_row = ctk.CTkFrame(pool_card, fg_color="transparent")
        btn_pool_row.grid(row=2, column=0, sticky="ew", padx=12, pady=(4, 10))
        btn_pool_row.grid_columnconfigure((0, 1), weight=1)

        self.btn_check_pool = ctk.CTkButton(
            btn_pool_row,
            text="TESTAR POOL (HEALTH CHECK)",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_CYAN,
            hover_color=TacticalTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            command=self._check_proxy_pool,
        )
        self.btn_check_pool.grid(row=0, column=0, padx=3, sticky="ew")

        ctk.CTkButton(
            btn_pool_row,
            text="ROTACIONAR PROXY ATIVO",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_GREEN,
            hover_color=TacticalTheme.ACCENT_GREEN_HOVER,
            text_color="#000000",
            command=self._rotate_active_proxy,
        ).grid(row=0, column=1, padx=3, sticky="ew")

        # Console de Logs do Servidor Proxy & Pool
        self.txt_proxy_log = ctk.CTkTextbox(
            self.tab_proxy,
            fg_color=TacticalTheme.BG_TERMINAL,
            text_color=TacticalTheme.ACCENT_CYAN,
            font=TacticalTheme.font(11),
        )
        self.txt_proxy_log.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=8, pady=(0, 8))
        self._proxy_log(
            "Servidor Proxy SOCKS5 Local pronto. Ative o switch acima para criar um proxy SOCKS5 imediato em 127.0.0.1:1080."
        )

    def _proxy_log(self, msg: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.txt_proxy_log.insert("end", f"[{ts}] {msg}\n")
        self.txt_proxy_log.see("end")

    def _toggle_socks5_server(self) -> None:
        if self.switch_socks_srv.get() == 1:
            try:
                host, port_s = self.entry_socks_bind.get().strip().split(":")
                port = int(port_s)
            except ValueError:
                self._proxy_log("[ERRO] Formato inválido. Use IP:PORTA (ex: 127.0.0.1:1080).")
                self.switch_socks_srv.deselect()
                return
            self.socks_server_running = True
            threading.Thread(target=self._socks5_accept_loop, args=(host, port), daemon=True).start()
        else:
            self.socks_server_running = False
            if self.socks_server_sock:
                try:
                    self.socks_server_sock.close()
                except Exception:
                    pass
            self.lbl_socks_stats.configure(
                text="Status: Parado | Clientes Ativos: 0", text_color=TacticalTheme.ACCENT_AMBER
            )
            self._proxy_log("[SOCKS5] Servidor Proxy local encerrado.")

    def _socks5_accept_loop(self, host: str, port: int) -> None:
        try:
            srv = SystemPlatform.create_configured_socket(timeout=1.0)
            srv.bind((host, port))
            srv.listen(32)
            self.socks_server_sock = srv
            self.after(
                0,
                lambda: self.lbl_socks_stats.configure(
                    text=f"Status: ESCUTANDO ({host}:{port}) | Clientes: 0",
                    text_color=TacticalTheme.ACCENT_GREEN,
                ),
            )
            self.after(
                0,
                lambda: self._proxy_log(
                    f"[SOCKS5 ATIVO] Servidor Proxy SOCKS5 escutando em {host}:{port} (Sem autenticação)"
                ),
            )
            while self.socks_server_running:
                try:
                    client_sock, addr = srv.accept()
                    self.socks_active_clients += 1
                    self.after(
                        0,
                        lambda: self.lbl_socks_stats.configure(
                            text=f"Status: ESCUTANDO ({host}:{port}) | Clientes: {self.socks_active_clients}"
                        ),
                    )
                    threading.Thread(
                        target=self._handle_socks5_client, args=(client_sock, addr), daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception as exc:
            self.after(0, lambda e=exc: self._proxy_log(f"[ERRO SOCKS5 BIND] {e}"))
            self.after(0, self.switch_socks_srv.deselect)
            self.socks_server_running = False

    def _handle_socks5_client(self, client_sock: socket.socket, addr) -> None:
        remote_sock = None
        try:
            client_sock.settimeout(5.0)
            # 1. Handshake SOCKS5
            hdr = client_sock.recv(2)
            if len(hdr) < 2 or hdr[0] != 0x05:
                return
            nmethods = hdr[1]
            client_sock.recv(nmethods)
            client_sock.sendall(b"\x05\x00")  # Sem autenticação (0x00)

            # 2. Requisição CONNECT
            req = client_sock.recv(4)
            if len(req) < 4 or req[1] != 0x01:
                return
            atyp = req[3]
            if atyp == 0x01:  # IPv4
                dst_addr = socket.inet_ntoa(client_sock.recv(4))
            elif atyp == 0x03:  # Domínio
                dlen = client_sock.recv(1)[0]
                dst_addr = client_sock.recv(dlen).decode("utf-8", errors="replace")
            else:
                return
            dst_port = struct.unpack("!H", client_sock.recv(2))[0]

            self.after(
                0,
                lambda a=addr, d=dst_addr, p=dst_port: self._proxy_log(
                    f"[SOCKS5 CONNECT] {a[0]}:{a[1]} -> {d}:{p}"
                ),
            )

            remote_sock = SystemPlatform.create_configured_socket(timeout=6.0)
            remote_sock.connect((dst_addr, dst_port))
            bind_ip, bind_port = remote_sock.getsockname()[:2]
            reply = b"\x05\x00\x00\x01" + socket.inet_aton(bind_ip) + struct.pack("!H", bind_port)
            client_sock.sendall(reply)

            # 3. Relay bidirecional
            sockets = [client_sock, remote_sock]
            while self.socks_server_running:
                r, _, _ = select.select(sockets, [], [], 1.0)
                if not r:
                    continue
                for s in r:
                    data = s.recv(8192)
                    if not data:
                        return
                    target = remote_sock if s is client_sock else client_sock
                    target.sendall(data)
        except Exception:
            pass
        finally:
            for s in (client_sock, remote_sock):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
            self.socks_active_clients = max(0, self.socks_active_clients - 1)

    def _check_proxy_pool(self) -> None:
        raw_lines = self.txt_proxy_pool.get("1.0", "end").splitlines()
        candidates = [ln.strip() for ln in raw_lines if ln.strip() and ":" in ln]
        if not candidates:
            self._proxy_log("[AVISO] Nenhum proxy válido na lista (use formato IP:PORTA).")
            return
        self.btn_check_pool.configure(state="disabled")
        self._proxy_log(f"[POOL CHECKER] Testando conectividade e latência de {len(candidates)} proxy(s)...")
        threading.Thread(target=self._pool_worker, args=(candidates,), daemon=True).start()

    def _test_single_proxy_socket(self, proxy_str: str) -> Tuple[str, bool, float]:
        try:
            host, port_s = proxy_str.split(":", 1)
            port = int(port_s)
            sock = SystemPlatform.create_configured_socket(timeout=2.5)
            start = time.perf_counter()
            res = sock.connect_ex((host, port))
            ms = (time.perf_counter() - start) * 1000.0
            sock.close()
            return proxy_str, (res == 0), ms
        except Exception:
            return proxy_str, False, 0.0

    def _pool_worker(self, candidates: List[str]) -> None:
        alive = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
            futures = [ex.submit(self._test_single_proxy_socket, c) for c in candidates]
            for fut in concurrent.futures.as_completed(futures):
                px, ok, ms = fut.result()
                if ok:
                    alive.append((px, ms))
                    self.after(
                        0,
                        lambda p=px, l=ms: self._proxy_log(f"  -> [ONLINE]  Proxy {p:<21} | Latência: {l:.2f} ms"),
                    )
                else:
                    self.after(
                        0,
                        lambda p=px: self._proxy_log(f"  -> [OFFLINE] Proxy {p:<21} | Sem resposta TCP"),
                    )
        alive.sort(key=lambda x: x[1])
        self.working_proxies = alive
        self.current_proxy_index = 0
        self.after(
            0,
            lambda: self._proxy_log(
                f"[RESUMO DO POOL] {len(alive)}/{len(candidates)} proxies ativos e prontos para rotação."
            ),
        )
        if alive:
            best_px, best_ms = alive[0]
            self.after(0, lambda b=best_px, m=best_ms: self._apply_rotated_proxy(b, m))
        self.after(0, lambda: self.btn_check_pool.configure(state="normal"))

    def _rotate_active_proxy(self) -> None:
        if not self.working_proxies:
            self._proxy_log(
                "[ROTAÇÃO] Execute primeiro o 'TESTAR POOL (HEALTH CHECK)' ou ative o Servidor SOCKS5 local."
            )
            return
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.working_proxies)
        px, ms = self.working_proxies[self.current_proxy_index]
        self._apply_rotated_proxy(px, ms)

    def _apply_rotated_proxy(self, px: str, ms: float) -> None:
        self.entry_proxy.delete(0, "end")
        self.entry_proxy.insert(0, px)
        self.seg_proto.set("SOCKS5")
        self._proxy_log(
            f"[ROTAÇÃO ATIVA] Proxy selecionado para encaminhamento: {px} ({ms:.2f} ms) [Modo SOCKS5]"
        )

    # =========================================================================
    # SUB-ABA 3: AUDITORIA DE ROTA HTTP & RESOLUÇÃO DNS
    # =========================================================================
    def _build_http_dns_tab(self) -> None:
        self.tab_http_dns.grid_columnconfigure(0, weight=1)
        self.tab_http_dns.grid_columnconfigure(1, weight=1)
        self.tab_http_dns.grid_rowconfigure(1, weight=1)

        # Card Esquerdo: Teste HTTP/HTTPS via Proxy
        proxy_card = ctk.CTkFrame(
            self.tab_http_dns,
            fg_color=TacticalTheme.BG_PANEL,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        proxy_card.grid(row=0, column=0, sticky="nsew", padx=(8, 4), pady=8)
        proxy_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            proxy_card,
            text="TESTE DE ENCAMINHAMENTO HTTP/SOCKS5 & CABEÇALHOS",
            font=TacticalTheme.font(12, "bold"),
            text_color=TacticalTheme.ACCENT_GREEN,
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))

        ctk.CTkLabel(proxy_card, text="Modo de Saída:", font=TacticalTheme.font(11)).grid(
            row=1, column=0, sticky="w", padx=12, pady=4
        )
        self.seg_proto = ctk.CTkSegmentedButton(
            proxy_card,
            values=["DIRETO", "HTTP", "SOCKS5"],
            font=TacticalTheme.font(11, "bold"),
            selected_color=TacticalTheme.ACCENT_CYAN,
            selected_hover_color=TacticalTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
        )
        self.seg_proto.set("SOCKS5")
        self.seg_proto.grid(row=1, column=1, sticky="ew", padx=12, pady=4)

        ctk.CTkLabel(proxy_card, text="Proxy Ativo (Host:Porta):", font=TacticalTheme.font(11)).grid(
            row=2, column=0, sticky="w", padx=12, pady=4
        )
        self.entry_proxy = ctk.CTkEntry(proxy_card, fg_color=TacticalTheme.BG_INPUT, font=TacticalTheme.font(11))
        self.entry_proxy.insert(0, "127.0.0.1:1080")
        self.entry_proxy.grid(row=2, column=1, sticky="ew", padx=12, pady=4)

        ctk.CTkLabel(proxy_card, text="User-Agent Customizado:", font=TacticalTheme.font(11)).grid(
            row=3, column=0, sticky="w", padx=12, pady=4
        )
        self.entry_ua = ctk.CTkEntry(proxy_card, fg_color=TacticalTheme.BG_INPUT, font=TacticalTheme.font(11))
        self.entry_ua.insert(0, "NetPulse-Tactical/2.4 (Proxy-Diagnostic)")
        self.entry_ua.grid(row=3, column=1, sticky="ew", padx=12, pady=4)

        self.btn_test_route = ctk.CTkButton(
            proxy_card,
            text="TESTAR ROTA VIA PROXY / DIRETO",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_GREEN,
            hover_color=TacticalTheme.ACCENT_GREEN_HOVER,
            text_color="#000000",
            command=self._test_egress,
        )
        self.btn_test_route.grid(row=4, column=0, columnspan=2, sticky="ew", padx=12, pady=(8, 10))

        # Card Direito: Resolução DNS
        dns_card = ctk.CTkFrame(
            self.tab_http_dns,
            fg_color=TacticalTheme.BG_PANEL,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        dns_card.grid(row=0, column=1, sticky="nsew", padx=(4, 8), pady=8)
        dns_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            dns_card,
            text="AUDITORIA DE RESOLUÇÃO DNS (A / AAAA / PTR)",
            font=TacticalTheme.font(12, "bold"),
            text_color=TacticalTheme.ACCENT_CYAN,
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))

        ctk.CTkLabel(dns_card, text="Domínio Alvo:", font=TacticalTheme.font(11)).grid(
            row=1, column=0, sticky="w", padx=12, pady=4
        )
        self.entry_dns_host = ctk.CTkEntry(dns_card, fg_color=TacticalTheme.BG_INPUT, font=TacticalTheme.font(11))
        self.entry_dns_host.insert(0, "cloudflare.com")
        self.entry_dns_host.grid(row=1, column=1, sticky="ew", padx=12, pady=4)

        self.switch_ipv6 = ctk.CTkSwitch(
            dns_card,
            text="Incluir Registros IPv6 (AAAA)",
            font=TacticalTheme.font(11),
            progress_color=TacticalTheme.ACCENT_CYAN,
        )
        self.switch_ipv6.select()
        self.switch_ipv6.grid(row=2, column=0, columnspan=2, sticky="w", padx=12, pady=8)

        self.btn_dns = ctk.CTkButton(
            dns_card,
            text="RESOLVER DNS & PTR REVERSO",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_CYAN,
            hover_color=TacticalTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            command=self._resolve_dns,
        )
        self.btn_dns.grid(row=3, column=0, columnspan=2, sticky="ew", padx=12, pady=(14, 10))

        self.txt_result = ctk.CTkTextbox(
            self.tab_http_dns,
            fg_color=TacticalTheme.BG_TERMINAL,
            text_color=TacticalTheme.TEXT_PRIMARY,
            font=TacticalTheme.font(11),
        )
        self.txt_result.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=8, pady=(0, 8))
        self._log("Auditoria HTTP/Proxy e DNS pronta.")

    def _log(self, text: str) -> None:
        self.txt_result.insert("end", text + "\n")
        self.txt_result.see("end")

    def _test_egress(self) -> None:
        mode = self.seg_proto.get()
        proxy_addr = self.entry_proxy.get().strip()
        ua = self.entry_ua.get().strip()
        self.btn_test_route.configure(state="disabled")
        threading.Thread(
            target=self._egress_worker, args=(mode, proxy_addr, ua), daemon=True
        ).start()

    def _egress_worker(self, mode: str, proxy_addr: str, ua: str) -> None:
        proxies = None
        if mode == "HTTP":
            proxies = {"http": f"http://{proxy_addr}", "https": f"http://{proxy_addr}"}
        elif mode == "SOCKS5":
            proxies = {"http": f"socks5h://{proxy_addr}", "https": f"socks5h://{proxy_addr}"}

        headers = {"User-Agent": ua, "X-Diagnostic-Probe": "NetPulse-Lab"}
        self.after(
            0,
            lambda: self._log(
                f"\n[ROTA] Testando saída via modo={mode} ({proxy_addr if proxies else 'Direto'})..."
            ),
        )
        start = time.perf_counter()
        try:
            resp = requests.get(
                "https://httpbin.org/get",
                proxies=proxies,
                headers=headers,
                timeout=8,
            )
            elapsed = (time.perf_counter() - start) * 1000.0
            data = resp.json()
            origin_ip = data.get("origin", "Desconhecido")
            echo_headers = json.dumps(data.get("headers", {}), indent=2, ensure_ascii=False)
            self.after(
                0,
                lambda: self._log(
                    f"[SUCESSO] Status HTTP {resp.status_code} em {elapsed:.1f} ms\n"
                    f"  -> IP de Saída Detectado: {origin_ip}\n"
                    f"  -> Cabeçalhos Recebidos pelo Endpoint:\n{echo_headers}"
                ),
            )
        except Exception as exc:
            self.after(0, lambda e=exc: self._log(f"[FALHA DE CONEXÃO] {e}"))
        finally:
            self.after(0, lambda: self.btn_test_route.configure(state="normal"))

    def _resolve_dns(self) -> None:
        domain = self.entry_dns_host.get().strip()
        inc_v6 = bool(self.switch_ipv6.get())
        threading.Thread(target=self._dns_worker, args=(domain, inc_v6), daemon=True).start()

    def _dns_worker(self, domain: str, inc_v6: bool) -> None:
        self.after(0, lambda: self._log(f"\n[DNS] Consultando registros para '{domain}'..."))
        start = time.perf_counter()
        try:
            infos = socket.getaddrinfo(domain, None)
            elapsed = (time.perf_counter() - start) * 1000.0
            seen = set()
            for family, _, _, _, sockaddr in infos:
                ip = sockaddr[0]
                if family == socket.AF_INET6 and not inc_v6:
                    continue
                rec_type = "AAAA (IPv6)" if family == socket.AF_INET6 else "A (IPv4)"
                if (rec_type, ip) not in seen:
                    seen.add((rec_type, ip))
                    try:
                        rev_host, _, _ = socket.gethostbyaddr(ip)
                    except Exception:
                        rev_host = "Sem PTR"
                    self.after(
                        0,
                        lambda r=rec_type, i=ip, p=rev_host: self._log(
                            f"  -> [{r:<11}] {i:<38} | PTR: {p}"
                        ),
                    )
            self.after(
                0,
                lambda: self._log(
                    f"[DNS] Resolução concluída em {elapsed:.2f} ms ({len(seen)} registro(s))."
                ),
            )
        except Exception as exc:
            self.after(0, lambda e=exc: self._log(f"[ERRO DNS] {e}"))
