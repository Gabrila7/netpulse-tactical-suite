"""
Camada de compatibilidade multiplataforma (Windows e Linux) para chamadas de sistema,
comandos de diagnóstico de rede, detecção de interfaces VPN (TUN/TAP/WireGuard),
janela Frameless nativa com suporte completo à Barra de Tarefas (WS_EX_APPWINDOW) e Alt+Tab,
resolução de DPI e parâmetros de sockets.
"""

import ctypes
import os
import platform
import socket
import subprocess
from typing import Dict, List, Tuple
import psutil


class SystemPlatform:
    OS_NAME: str = platform.system()
    IS_WINDOWS: bool = OS_NAME == "Windows"
    IS_LINUX: bool = OS_NAME == "Linux"

    VPN_KEYWORDS = (
        "tun",
        "tap",
        "wg",
        "wireguard",
        "openvpn",
        "wintun",
        "ppp",
        "vpn",
        "tailscale",
        "zerotier",
        "nordlynx",
        "proton",
        "utun",
    )

    @classmethod
    def configure_dpi_awareness(cls) -> None:
        """Ativa nitidez de fontes (High-DPI) nativo no Windows."""
        if cls.IS_WINDOWS:
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                try:
                    ctypes.windll.user32.SetProcessDPIAware()
                except Exception:
                    pass

    @classmethod
    def apply_native_frameless_style(cls, tk_window) -> None:
        """
        Ativa janela 100% Frameless (sem barra de título do SO) e registra a janela
        na Barra de Tarefas do Windows e no Alt+Tab (substituindo WS_EX_TOOLWINDOW por WS_EX_APPWINDOW),
        além de ativar cantos arredondados nativos via DWM no Windows 11.
        """
        tk_window.overrideredirect(True)
        if cls.IS_WINDOWS:
            try:
                tk_window.update_idletasks()
                hwnd = ctypes.windll.user32.GetParent(tk_window.winfo_id())
                if not hwnd:
                    hwnd = tk_window.winfo_id()

                GWL_STYLE = -16
                GWL_EXSTYLE = -20
                WS_MINIMIZEBOX = 0x00020000
                WS_SYSMENU = 0x00080000
                WS_EX_APPWINDOW = 0x00040000

                SW_HIDE = 0
                SW_SHOW = 5

                # Oculta brevemente o HWND para o Explorer registrar a troca de ToolWindow -> AppWindow na Taskbar
                ctypes.windll.user32.ShowWindow(hwnd, SW_HIDE)

                style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_STYLE)
                ctypes.windll.user32.SetWindowLongW(hwnd, GWL_STYLE, style | WS_MINIMIZEBOX | WS_SYSMENU)
                ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, WS_EX_APPWINDOW)

                # Aplica cantos arredondados e modo escuro nativo do Windows 11 (DWM)
                try:
                    DWMWA_USE_IMMERSIVE_DARK_MODE = 20
                    dark_mode = ctypes.c_int(1)
                    ctypes.windll.dwmapi.DwmSetWindowAttribute(
                        hwnd,
                        DWMWA_USE_IMMERSIVE_DARK_MODE,
                        ctypes.byref(dark_mode),
                        ctypes.sizeof(dark_mode),
                    )
                    DWMWA_WINDOW_CORNER_PREFERENCE = 33
                    DWMWCP_ROUND = ctypes.c_int(2)
                    ctypes.windll.dwmapi.DwmSetWindowAttribute(
                        hwnd,
                        DWMWA_WINDOW_CORNER_PREFERENCE,
                        ctypes.byref(DWMWCP_ROUND),
                        ctypes.sizeof(DWMWCP_ROUND),
                    )
                except Exception:
                    pass

                ctypes.windll.user32.ShowWindow(hwnd, SW_SHOW)
                ctypes.windll.user32.SetForegroundWindow(hwnd)
            except Exception:
                pass

    @classmethod
    def minimize_native_window(cls, tk_window) -> None:
        """Minimiza a janela para a Barra de Tarefas preservando o ícone."""
        if cls.IS_WINDOWS:
            try:
                hwnd = ctypes.windll.user32.GetParent(tk_window.winfo_id()) or tk_window.winfo_id()
                SW_MINIMIZE = 6
                ctypes.windll.user32.ShowWindow(hwnd, SW_MINIMIZE)
                return
            except Exception:
                pass
        tk_window.iconify()

    @classmethod
    def get_system_summary(cls) -> str:
        """Retorna string técnica identificando o ambiente de execução."""
        arch = platform.machine()
        release = platform.release()
        hostname = socket.gethostname()
        return f"SO: {cls.OS_NAME} {release} ({arch}) | Host: {hostname}"

    @classmethod
    def build_ping_command(cls, host: str, count: int = 4, timeout_sec: int = 2) -> List[str]:
        """Monta comando ICMP ping nativo compatível com Windows e Linux."""
        if cls.IS_WINDOWS:
            return ["ping", "-n", str(count), "-w", str(timeout_sec * 1000), host]
        return ["ping", "-c", str(count), "-W", str(timeout_sec), host]

    @classmethod
    def build_traceroute_command(cls, host: str, max_hops: int = 15) -> List[str]:
        """Monta comando de rastreamento de rota nativo para Windows (tracert) ou Linux (tracepath)."""
        if cls.IS_WINDOWS:
            return ["tracert", "-d", "-h", str(max_hops), "-w", "1000", host]
        return ["tracepath", "-n", "-m", str(max_hops), host]

    @classmethod
    def run_native_command(cls, command: List[str], timeout: int = 25) -> Tuple[int, str]:
        """Executa comando de diagnóstico sem abrir janela de console secundária no Windows."""
        creation_flags = 0
        if cls.IS_WINDOWS:
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=creation_flags,
                encoding="utf-8",
                errors="replace",
            )
            output = proc.stdout.strip() or proc.stderr.strip()
            return proc.returncode, output
        except FileNotFoundError:
            return 127, f"Comando '{command[0]}' não encontrado no PATH do sistema ({cls.OS_NAME})."
        except subprocess.TimeoutExpired:
            return 124, f"Tempo limite excedido ({timeout}s) ao executar: {' '.join(command)}"
        except Exception as exc:
            return 1, f"Erro ao executar comando nativo: {exc}"

    @classmethod
    def create_configured_socket(cls, timeout: float = 2.0) -> socket.socket:
        """Cria socket TCP com opções multiplataforma de reutilização de endereço."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if cls.IS_LINUX and hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        return sock

    @classmethod
    def is_elevated(cls) -> bool:
        """Verifica se o processo atual possui privilégios administrativos/root."""
        if cls.IS_WINDOWS:
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False

    @classmethod
    def inspect_network_interfaces(cls) -> List[Dict[str, str]]:
        """
        Retorna todas as interfaces de rede do sistema, destacando adaptadores
        virtuais de VPN/Túnel (TUN, TAP, WireGuard, OpenVPN, PPP, Wintun).
        """
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        results = []

        for iface_name, addr_list in addrs.items():
            st = stats.get(iface_name)
            is_up = st.isup if st else False
            mtu = st.mtu if st else 0
            speed = st.speed if st else 0

            ipv4 = "-"
            netmask = "-"
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ipv4 = addr.address
                    netmask = addr.netmask or "-"
                    break

            lower_name = iface_name.lower()
            is_vpn = any(k in lower_name for k in cls.VPN_KEYWORDS)
            iface_type = "VPN / TÚNEL" if is_vpn else "FÍSICA / SISTEMA"

            results.append(
                {
                    "name": iface_name,
                    "type": iface_type,
                    "is_vpn": "1" if is_vpn else "0",
                    "status": "UP (ATIVO)" if is_up else "DOWN",
                    "ipv4": ipv4,
                    "netmask": netmask,
                    "mtu": str(mtu),
                    "speed": f"{speed} Mbps" if speed > 0 else "Virtual",
                }
            )

        results.sort(key=lambda x: (x["is_vpn"] != "1", x["status"] != "UP (ATIVO)", x["name"]))
        return results

    @classmethod
    def get_system_dns_servers(cls) -> List[str]:
        """Obtém os servidores DNS configurados no sistema operacional."""
        dns_servers = []
        if cls.IS_WINDOWS:
            code, out = cls.run_native_command(["netsh", "interface", "ip", "show", "dns"], timeout=8)
            if code == 0:
                for line in out.splitlines():
                    parts = line.strip().split()
                    for token in parts:
                        if token.count(".") == 3 and all(p.isdigit() for p in token.split(".")):
                            if token not in dns_servers:
                                dns_servers.append(token)
        else:
            try:
                with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2 and parts[1] not in dns_servers:
                                dns_servers.append(parts[1])
            except Exception:
                pass
        return dns_servers or ["Não detectado"]
