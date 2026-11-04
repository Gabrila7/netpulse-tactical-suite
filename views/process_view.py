"""
Aba 4: Inspeção de Processos e Sockets do Sistema.
Monitora conexões TCP e UDP ativas na máquina local via psutil, correlacionando
descritores de sockets com PID e nome do processo do Sistema Operacional.
"""

import threading
import customtkinter as ctk
import psutil
from core.theme import TacticalTheme
from core.system_platform import SystemPlatform


class ProcessView(ctk.CTkFrame):
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
            text="[04] INSPEÇÃO DE PROCESSOS & SOCKETS ATIVOS DO SISTEMA",
            font=TacticalTheme.font(14, "bold"),
            text_color=TacticalTheme.ACCENT_CYAN,
        ).pack(anchor="w", padx=14, pady=(10, 2))
        priv_status = "Elevado (Admin/Root)" if SystemPlatform.is_elevated() else "Usuário Padrão"
        ctk.CTkLabel(
            header,
            text=f"Mapeamento de sockets TCP/UDP abertos e processos vinculados | Contexto: {priv_status}",
            font=TacticalTheme.font(11),
            text_color=TacticalTheme.TEXT_SECONDARY,
        ).pack(anchor="w", padx=14, pady=(0, 10))

        # Barra de Filtros
        filter_bar = ctk.CTkFrame(
            self,
            fg_color=TacticalTheme.BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        filter_bar.grid(row=1, column=0, sticky="ew", padx=14, pady=6)

        ctk.CTkLabel(filter_bar, text="Protocolo:", font=TacticalTheme.font(11)).pack(
            side="left", padx=(12, 6), pady=10
        )
        self.seg_proto = ctk.CTkSegmentedButton(
            filter_bar,
            values=["TODOS", "TCP", "UDP"],
            font=TacticalTheme.font(11, "bold"),
            selected_color=TacticalTheme.ACCENT_CYAN,
            selected_hover_color=TacticalTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
        )
        self.seg_proto.set("TODOS")
        self.seg_proto.pack(side="left", padx=6, pady=10)

        self.switch_listen = ctk.CTkSwitch(
            filter_bar,
            text="Apenas LISTEN / ESTABLISHED",
            font=TacticalTheme.font(11),
            progress_color=TacticalTheme.ACCENT_GREEN,
        )
        self.switch_listen.pack(side="left", padx=14, pady=10)

        ctk.CTkLabel(filter_bar, text="Filtro (Processo/Porta):", font=TacticalTheme.font(11)).pack(
            side="left", padx=(8, 4), pady=10
        )
        self.entry_filter = ctk.CTkEntry(
            filter_bar,
            fg_color=TacticalTheme.BG_INPUT,
            font=TacticalTheme.font(11),
            width=160,
        )
        self.entry_filter.pack(side="left", padx=6, pady=10)

        self.btn_refresh = ctk.CTkButton(
            filter_bar,
            text="ATUALIZAR SOCKETS",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_GREEN,
            hover_color=TacticalTheme.ACCENT_GREEN_HOVER,
            text_color="#000000",
            command=self.refresh_sockets,
        )
        self.btn_refresh.pack(side="right", padx=12, pady=10)

        # Tabela Monoespaçada de Sockets
        table_card = ctk.CTkFrame(self, fg_color=TacticalTheme.BG_CARD, corner_radius=8)
        table_card.grid(row=2, column=0, sticky="nsew", padx=14, pady=(6, 14))
        table_card.grid_rowconfigure(0, weight=1)
        table_card.grid_columnconfigure(0, weight=1)

        self.txt_table = ctk.CTkTextbox(
            table_card,
            fg_color=TacticalTheme.BG_TERMINAL,
            text_color=TacticalTheme.ACCENT_CYAN,
            font=TacticalTheme.font(11),
        )
        self.txt_table.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.refresh_sockets()

    def refresh_sockets(self) -> None:
        self.btn_refresh.configure(state="disabled")
        proto_mode = self.seg_proto.get()
        only_active = bool(self.switch_listen.get())
        query = self.entry_filter.get().strip().lower()
        threading.Thread(
            target=self._collect_sockets,
            args=(proto_mode, only_active, query),
            daemon=True,
        ).start()

    def _collect_sockets(self, proto_mode: str, only_active: bool, query: str) -> None:
        kind_map = {"TODOS": "inet", "TCP": "tcp", "UDP": "udp"}
        kind = kind_map.get(proto_mode, "inet")

        lines = [
            f"{'PROTO':<6} | {'ENDEREÇO LOCAL':<24} | {'ENDEREÇO REMOTO':<24} | {'STATUS':<13} | {'PID':<7} | {'PROCESSO'}",
            "-" * 102,
        ]
        count = 0
        try:
            conns = psutil.net_connections(kind=kind)
            for c in conns:
                proto = "TCP" if c.type == 1 else "UDP"
                status = c.status if c.status else "NONE"
                if only_active and status not in ("LISTEN", "ESTABLISHED"):
                    continue

                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                pid = c.pid or 0
                proc_name = "Sistema/Kernel"
                if pid > 0:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "Acesso Restrito"

                row_str = f"{proto:<6} | {laddr:<24} | {raddr:<24} | {status:<13} | {pid:<7} | {proc_name}"
                if query and query not in row_str.lower():
                    continue
                lines.append(row_str)
                count += 1
        except Exception as exc:
            lines.append(f"[ERRO AO CONSULTAR SOCKETS DO SO]: {exc}")

        lines.append("-" * 102)
        lines.append(f"Total de conexões/sockets listados: {count}")
        output_text = "\n".join(lines)

        def _update():
            self.txt_table.delete("1.0", "end")
            self.txt_table.insert("1.0", output_text)
            self.btn_refresh.configure(state="normal")

        self.after(0, _update)
