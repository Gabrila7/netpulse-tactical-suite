"""
Aba 2: Varredura de Rede e Diagnóstico de Portas.
Permite inspecionar portas de serviços em hosts de laboratório/autorizados,
identificar serviços padrões IANA e executar diagnósticos de ICMP Ping e Rota multiplataforma.
"""

import concurrent.futures
import socket
import threading
import time
from typing import List
import customtkinter as ctk
from core.theme import TacticalTheme
from core.system_platform import SystemPlatform


class ScannerView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=TacticalTheme.BG_PANEL, corner_radius=10, **kwargs)
        self._build_ui()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Cabeçalho
        header = ctk.CTkFrame(self, fg_color=TacticalTheme.BG_CARD, corner_radius=8)
        header.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 8))
        ctk.CTkLabel(
            header,
            text="[02] DIAGNÓSTICO DE SERVIÇOS, PORTAS & VERIFICAÇÃO DE ROTAS",
            font=TacticalTheme.font(14, "bold"),
            text_color=TacticalTheme.ACCENT_CYAN,
        ).pack(anchor="w", padx=14, pady=(10, 2))
        ctk.CTkLabel(
            header,
            text="Auditoria de conectividade de portas TCP, resolução de serviços IANA e rastreamento de rota (Windows/Linux).",
            font=TacticalTheme.font(11),
            text_color=TacticalTheme.TEXT_SECONDARY,
        ).pack(anchor="w", padx=14, pady=(0, 10))

        # Barra de Controles
        ctrl = ctk.CTkFrame(
            self,
            fg_color=TacticalTheme.BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        ctrl.grid(row=1, column=0, sticky="ew", padx=14, pady=6)
        ctrl.grid_columnconfigure(1, weight=1)
        ctrl.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(ctrl, text="Host / IP:", font=TacticalTheme.font(11)).grid(
            row=0, column=0, sticky="w", padx=12, pady=8
        )
        self.entry_host = ctk.CTkEntry(ctrl, fg_color=TacticalTheme.BG_INPUT, font=TacticalTheme.font(11))
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.grid(row=0, column=1, sticky="ew", padx=8, pady=8)

        ctk.CTkLabel(ctrl, text="Portas (CSV ou Intervalo):", font=TacticalTheme.font(11)).grid(
            row=0, column=2, sticky="w", padx=12, pady=8
        )
        self.entry_ports = ctk.CTkEntry(ctrl, fg_color=TacticalTheme.BG_INPUT, font=TacticalTheme.font(11))
        self.entry_ports.insert(0, "22, 80, 443, 3306, 5432, 8000-8010")
        self.entry_ports.grid(row=0, column=3, sticky="ew", padx=8, pady=8)

        ctk.CTkLabel(ctrl, text="Timeout (ms):", font=TacticalTheme.font(11)).grid(
            row=1, column=0, sticky="w", padx=12, pady=6
        )
        self.slider_timeout = ctk.CTkSlider(
            ctrl,
            from_=150,
            to=3000,
            number_of_steps=57,
            button_color=TacticalTheme.ACCENT_CYAN,
        )
        self.slider_timeout.set(600)
        self.slider_timeout.grid(row=1, column=1, sticky="ew", padx=8, pady=6)

        self.switch_banner = ctk.CTkSwitch(
            ctrl,
            text="Leitura Passiva de Cabeçalho/Banner",
            font=TacticalTheme.font(11),
            progress_color=TacticalTheme.ACCENT_GREEN,
        )
        self.switch_banner.select()
        self.switch_banner.grid(row=1, column=2, columnspan=2, sticky="w", padx=12, pady=6)

        btn_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        btn_row.grid(row=2, column=0, columnspan=4, sticky="ew", padx=12, pady=(4, 12))

        self.btn_scan = ctk.CTkButton(
            btn_row,
            text="INSPECIONAR PORTAS TCP",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_GREEN,
            hover_color=TacticalTheme.ACCENT_GREEN_HOVER,
            text_color="#000000",
            command=self._run_port_diagnostic,
        )
        self.btn_scan.pack(side="left", padx=(0, 8))

        self.btn_ping = ctk.CTkButton(
            btn_row,
            text="ICMP PING NATIVO",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_CYAN,
            hover_color=TacticalTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            command=self._run_ping,
        )
        self.btn_ping.pack(side="left", padx=8)

        self.btn_trace = ctk.CTkButton(
            btn_row,
            text="VERIFICAR ROTA (TRACEROUTE)",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.BG_INPUT,
            hover_color=TacticalTheme.ACCENT_DARK_BORDER,
            command=self._run_traceroute,
        )
        self.btn_trace.pack(side="left", padx=8)

        # Saída
        out_card = ctk.CTkFrame(self, fg_color=TacticalTheme.BG_CARD, corner_radius=8)
        out_card.grid(row=2, column=0, sticky="nsew", padx=14, pady=(6, 14))
        out_card.grid_rowconfigure(0, weight=1)
        out_card.grid_columnconfigure(0, weight=1)

        self.txt_output = ctk.CTkTextbox(
            out_card,
            fg_color=TacticalTheme.BG_TERMINAL,
            text_color=TacticalTheme.TEXT_PRIMARY,
            font=TacticalTheme.font(11),
        )
        self.txt_output.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self._append("Pronto para diagnóstico de portas e verificação de conectividade.")

    def _append(self, text: str) -> None:
        self.txt_output.insert("end", text + "\n")
        self.txt_output.see("end")

    @staticmethod
    def _parse_ports(raw: str) -> List[int]:
        ports = set()
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start_s, end_s = part.split("-", 1)
                start_p, end_p = int(start_s), int(end_s)
                for p in range(min(start_p, end_p), max(start_p, end_p) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            else:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
        return sorted(ports)

    def _run_port_diagnostic(self) -> None:
        host = self.entry_host.get().strip()
        raw_ports = self.entry_ports.get().strip()
        timeout_sec = float(self.slider_timeout.get()) / 1000.0
        grab_banner = bool(self.switch_banner.get())

        try:
            ports = self._parse_ports(raw_ports)
            if not ports:
                raise ValueError("Nenhuma porta válida especificada.")
        except Exception as exc:
            self._append(f"[ERRO] Lista de portas inválida: {exc}")
            return

        self.btn_scan.configure(state="disabled")
        threading.Thread(
            target=self._scan_worker,
            args=(host, ports, timeout_sec, grab_banner),
            daemon=True,
        ).start()

    def _check_single_port(self, ip: str, port: int, timeout: float, grab_banner: bool):
        sock = SystemPlatform.create_configured_socket(timeout=timeout)
        start = time.perf_counter()
        try:
            res = sock.connect_ex((ip, port))
            latency_ms = (time.perf_counter() - start) * 1000.0
            if res == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "desconhecido"
                banner_info = ""
                if grab_banner:
                    try:
                        sock.settimeout(0.6)
                        data = sock.recv(128)
                        if data:
                            banner_info = data.decode("utf-8", errors="replace").strip().splitlines()[0][:50]
                    except Exception:
                        pass
                return port, True, latency_ms, service, banner_info
            return port, False, latency_ms, "", ""
        except Exception:
            return port, False, 0.0, "", ""
        finally:
            sock.close()

    def _scan_worker(self, host: str, ports: List[int], timeout: float, grab_banner: bool) -> None:
        try:
            resolved_ip = socket.gethostbyname(host)
        except socket.gaierror as exc:
            self.after(0, lambda e=exc: self._append(f"[ERRO DNS] Não foi possível resolver '{host}': {e}"))
            self.after(0, lambda: self.btn_scan.configure(state="normal"))
            return

        self.after(
            0,
            lambda: self._append(
                f"\n=== INSPECIONANDO {host} ({resolved_ip}) | {len(ports)} portas | Timeout: {int(timeout*1000)}ms ==="
            ),
        )
        open_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
            futures = [
                executor.submit(self._check_single_port, resolved_ip, p, timeout, grab_banner)
                for p in ports
            ]
            for fut in concurrent.futures.as_completed(futures):
                port, is_open, ms, service, banner = fut.result()
                if is_open:
                    open_count += 1
                    extra = f" | Banner: {banner}" if banner else ""
                    self.after(
                        0,
                        lambda p=port, s=service, l=ms, ex=extra: self._append(
                            f"  [ABERTA] Porta {p:<5}/TCP | Serviço: {s:<14} | RTT: {l:6.2f} ms{ex}"
                        ),
                    )
        self.after(
            0,
            lambda: self._append(
                f"=== Diagnóstico concluído: {open_count} porta(s) ativa(s) de {len(ports)} testadas. ==="
            ),
        )
        self.after(0, lambda: self.btn_scan.configure(state="normal"))

    def _run_ping(self) -> None:
        host = self.entry_host.get().strip()
        cmd = SystemPlatform.build_ping_command(host, count=4)
        self._append(f"\n[EXEC] {' '.join(cmd)}")
        threading.Thread(target=self._cmd_worker, args=(cmd,), daemon=True).start()

    def _run_traceroute(self) -> None:
        host = self.entry_host.get().strip()
        cmd = SystemPlatform.build_traceroute_command(host, max_hops=15)
        self._append(f"\n[EXEC] {' '.join(cmd)}")
        threading.Thread(target=self._cmd_worker, args=(cmd,), daemon=True).start()

    def _cmd_worker(self, cmd: List[str]) -> None:
        code, output = SystemPlatform.run_native_command(cmd, timeout=30)
        self.after(0, lambda: self._append(f"{output}\n[Código de Saída: {code}]"))
