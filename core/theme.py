"""
Definições de paleta de cores, tipografia e constantes visuais (Estética Dark/Tática).
"""

import platform


class TacticalTheme:
    # Paleta de fundos (Preto Fosco / Cinza Chumbo Profundo)
    BG_ROOT = "#090b10"
    BG_SIDEBAR = "#0d1117"
    BG_PANEL = "#11161f"
    BG_CARD = "#161c28"
    BG_TERMINAL = "#06080c"
    BG_INPUT = "#0c1017"

    # Acentos Visuais (Ciano Tático, Verde Neon, Âmbar e Alerta)
    ACCENT_CYAN = "#00f0ff"
    ACCENT_CYAN_HOVER = "#00b8c4"
    ACCENT_GREEN = "#00e676"
    ACCENT_GREEN_HOVER = "#00b359"
    ACCENT_AMBER = "#ffab00"
    ACCENT_RED = "#ff3d57"
    ACCENT_DARK_BORDER = "#1e2636"

    # Textos
    TEXT_PRIMARY = "#e6edf3"
    TEXT_SECONDARY = "#8b949e"
    TEXT_MUTED = "#484f58"

    # Fontes monoespaçadas adaptadas por SO
    @staticmethod
    def get_mono_font() -> str:
        sys_name = platform.system()
        if sys_name == "Windows":
            return "Consolas"
        elif sys_name == "Darwin":
            return "Menlo"
        return "DejaVu Sans Mono"

    @classmethod
    def font(cls, size: int = 12, weight: str = "normal") -> tuple:
        return (cls.get_mono_font(), size, weight)
