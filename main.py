"""
NetPulse Tactical Diagnostic Suite - Aplicação Desktop Nativa (CustomTkinter).
Janela Frameless com suporte completo à Barra de Tarefas e Alt+Tab no Windows (WS_EX_APPWINDOW),
modo Overlay (Fixar no Topo ativo por padrão), menu lateral compacto em abas e telemetria.
"""

import customtkinter as ctk
import psutil
from core.theme import TacticalTheme
from core.system_platform import SystemPlatform
from views.tunnel_view import TunnelView
from views.scanner_view import ScannerView
from views.routing_view import RoutingView
from views.process_view import ProcessView
from views.crypto_view import CryptoView


class NetPulseApp(ctk.CTk):
    def __init__(self):
        SystemPlatform.configure_dpi_awareness()
        super().__init__()

        ctk.set_appearance_mode("dark")
        self.title("NetPulse // Tactical Network & System Diagnostic Suite")
        self.geometry("1180x740+120+70")
        self.minsize(1020, 640)
        self.configure(fg_color=TacticalTheme.BG_ROOT)

        # Mantém a janela visível no topo (Overlay) por padrão ao clicar em outras janelas
        self._is_topmost = True
        self._is_maximized = False
        self._normal_geometry = "1180x740+120+70"

        # Posição para arrastar a janela pela barra superior
        self._drag_x = 0
        self._drag_y = 0

        self.views = {}
        self.nav_buttons = {}

        self._build_shell()
        self._select_tab("tunnels")
        self._update_telemetry_bar()

        # Aplica estilo Frameless nativo preservando ícone na Barra de Tarefas, Alt+Tab e Overlay
        self.after(20, self._init_window_behavior)

    def _init_window_behavior(self) -> None:
        SystemPlatform.apply_native_frameless_style(self)
        self.attributes("-topmost", self._is_topmost)

    def _build_shell(self) -> None:
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # 1. Barra de Título Customizada (Frameless Drag Bar)
        self.title_bar = ctk.CTkFrame(
            self,
            fg_color=TacticalTheme.BG_SIDEBAR,
            height=38,
            corner_radius=0,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        self.title_bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.title_bar.bind("<ButtonPress-1>", self._start_move)
        self.title_bar.bind("<B1-Motion>", self._on_move)
        self.title_bar.bind("<Double-Button-1>", lambda _e: self._toggle_maximize())

        lbl_badge = ctk.CTkLabel(
            self.title_bar,
            text=" ◆ NETPULSE // TACTICAL DIAGNOSTIC CONSOLE v2.5 ",
            font=TacticalTheme.font(12, "bold"),
            text_color=TacticalTheme.ACCENT_CYAN,
        )
        lbl_badge.pack(side="left", padx=12, pady=6)
        lbl_badge.bind("<ButtonPress-1>", self._start_move)
        lbl_badge.bind("<B1-Motion>", self._on_move)
        lbl_badge.bind("<Double-Button-1>", lambda _e: self._toggle_maximize())

        lbl_sys = ctk.CTkLabel(
            self.title_bar,
            text=SystemPlatform.get_system_summary(),
            font=TacticalTheme.font(10),
            text_color=TacticalTheme.TEXT_SECONDARY,
        )
        lbl_sys.pack(side="left", padx=12)
        lbl_sys.bind("<ButtonPress-1>", self._start_move)
        lbl_sys.bind("<B1-Motion>", self._on_move)

        # Botões de controle da janela (Fechar / Maximizar / Minimizar / Overlay Pin)
        ctk.CTkButton(
            self.title_bar,
            text="✕",
            width=36,
            height=26,
            corner_radius=4,
            fg_color="transparent",
            hover_color=TacticalTheme.ACCENT_RED,
            font=TacticalTheme.font(12, "bold"),
            command=self.destroy,
        ).pack(side="right", padx=(2, 8), pady=5)

        ctk.CTkButton(
            self.title_bar,
            text="▢",
            width=36,
            height=26,
            corner_radius=4,
            fg_color="transparent",
            hover_color=TacticalTheme.ACCENT_DARK_BORDER,
            font=TacticalTheme.font(12),
            command=self._toggle_maximize,
        ).pack(side="right", padx=2, pady=5)

        ctk.CTkButton(
            self.title_bar,
            text="—",
            width=36,
            height=26,
            corner_radius=4,
            fg_color="transparent",
            hover_color=TacticalTheme.ACCENT_DARK_BORDER,
            font=TacticalTheme.font(12),
            command=self._minimize_window,
        ).pack(side="right", padx=2, pady=5)

        self.btn_pin = ctk.CTkButton(
            self.title_bar,
            text="📌 FIXAR TOPO: ON",
            width=130,
            height=24,
            corner_radius=4,
            fg_color=TacticalTheme.ACCENT_GREEN,
            hover_color=TacticalTheme.ACCENT_GREEN_HOVER,
            text_color="#000000",
            font=TacticalTheme.font(10, "bold"),
            command=self._toggle_topmost,
        )
        self.btn_pin.pack(side="right", padx=8, pady=5)

        # 2. Menu Lateral Compacto em Abas (Sidebar)
        self.sidebar = ctk.CTkFrame(
            self,
            fg_color=TacticalTheme.BG_SIDEBAR,
            width=230,
            corner_radius=0,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        self.sidebar.grid(row=1, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        ctk.CTkLabel(
            self.sidebar,
            text="MÓDULOS DE OPERAÇÃO",
            font=TacticalTheme.font(10, "bold"),
            text_color=TacticalTheme.TEXT_MUTED,
        ).pack(anchor="w", padx=16, pady=(16, 8))

        tabs_spec = [
            ("tunnels", "01 // Túneis & Latência", TunnelView),
            ("scanner", "02 // Portas & Rotas", ScannerView),
            ("routing", "03 // VPN & Proxy Suite", RoutingView),
            ("process", "04 // Processos & Sockets", ProcessView),
            ("crypto", "05 // Cripto & Codificação", CryptoView),
        ]

        # Container Principal de Conteúdo
        self.content_area = ctk.CTkFrame(self, fg_color=TacticalTheme.BG_ROOT, corner_radius=0)
        self.content_area.grid(row=1, column=1, sticky="nsew", padx=10, pady=10)
        self.content_area.grid_rowconfigure(0, weight=1)
        self.content_area.grid_columnconfigure(0, weight=1)

        for key, label, view_cls in tabs_spec:
            btn = ctk.CTkButton(
                self.sidebar,
                text=label,
                anchor="w",
                height=38,
                corner_radius=6,
                font=TacticalTheme.font(11, "bold"),
                fg_color="transparent",
                text_color=TacticalTheme.TEXT_SECONDARY,
                hover_color=TacticalTheme.BG_CARD,
                command=lambda k=key: self._select_tab(k),
            )
            btn.pack(fill="x", padx=10, pady=4)
            self.nav_buttons[key] = btn

            view_instance = view_cls(self.content_area)
            self.views[key] = view_instance

        # Rodapé de Telemetria na Sidebar
        telemetry_box = ctk.CTkFrame(
            self.sidebar,
            fg_color=TacticalTheme.BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        telemetry_box.pack(side="bottom", fill="x", padx=10, pady=12)

        self.lbl_cpu = ctk.CTkLabel(
            telemetry_box,
            text="CPU: 0.0% | RAM: 0.0%",
            font=TacticalTheme.font(10),
            text_color=TacticalTheme.ACCENT_GREEN,
        )
        self.lbl_cpu.pack(anchor="w", padx=10, pady=(8, 2))

        self.lbl_net_io = ctk.CTkLabel(
            telemetry_box,
            text="TX: 0 KB | RX: 0 KB",
            font=TacticalTheme.font(10),
            text_color=TacticalTheme.ACCENT_CYAN,
        )
        self.lbl_net_io.pack(anchor="w", padx=10, pady=(0, 8))

    def _select_tab(self, tab_key: str) -> None:
        for k, view in self.views.items():
            view.grid_forget()
        for k, btn in self.nav_buttons.items():
            if k == tab_key:
                btn.configure(
                    fg_color=TacticalTheme.BG_CARD,
                    text_color=TacticalTheme.ACCENT_CYAN,
                    border_width=1,
                    border_color=TacticalTheme.ACCENT_CYAN,
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    text_color=TacticalTheme.TEXT_SECONDARY,
                    border_width=0,
                )
        self.views[tab_key].grid(row=0, column=0, sticky="nsew")

    def _start_move(self, event) -> None:
        self._drag_x = event.x
        self._drag_y = event.y

    def _on_move(self, event) -> None:
        if self._is_maximized:
            return
        x = self.winfo_x() - self._drag_x + event.x
        y = self.winfo_y() - self._drag_y + event.y
        self.geometry(f"+{x}+{y}")

    def _toggle_topmost(self) -> None:
        self._is_topmost = not self._is_topmost
        self.attributes("-topmost", self._is_topmost)
        if self._is_topmost:
            self.btn_pin.configure(
                text="📌 FIXAR TOPO: ON",
                fg_color=TacticalTheme.ACCENT_GREEN,
                text_color="#000000",
            )
        else:
            self.btn_pin.configure(
                text="📌 FIXAR TOPO: OFF",
                fg_color=TacticalTheme.BG_CARD,
                text_color=TacticalTheme.TEXT_SECONDARY,
            )

    def _toggle_maximize(self) -> None:
        if not self._is_maximized:
            self._normal_geometry = self.geometry()
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight() - 48
            self.geometry(f"{sw}x{sh}+0+0")
            self._is_maximized = True
        else:
            self.geometry(self._normal_geometry)
            self._is_maximized = False

    def _minimize_window(self) -> None:
        SystemPlatform.minimize_native_window(self)

    def _update_telemetry_bar(self) -> None:
        try:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            net = psutil.net_io_counters()
            tx_mb = net.bytes_sent / (1024 * 1024)
            rx_mb = net.bytes_recv / (1024 * 1024)
            self.lbl_cpu.configure(text=f"CPU: {cpu:4.1f}% | RAM: {ram:4.1f}%")
            self.lbl_net_io.configure(text=f"TX: {tx_mb:,.1f} MB | RX: {rx_mb:,.1f} MB")
        except Exception:
            pass
        self.after(2000, self._update_telemetry_bar)


if __name__ == "__main__":
    app = NetPulseApp()
    app.mainloop()
