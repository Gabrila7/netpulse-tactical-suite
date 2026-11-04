"""
Aba 5: Caixa de Ferramentas de Criptografia e Codificação.
Inclui codificador/decodificador Base64 e Hexadecimal, calculadora de hashes
(MD5, SHA-1, SHA-256, SHA-512), HMAC-SHA256 e gerador criptográfico de chaves/senhas.
"""

import base64
import hashlib
import hmac
import secrets
import string
import urllib.parse
import customtkinter as ctk
from core.theme import TacticalTheme


class CryptoView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=TacticalTheme.BG_PANEL, corner_radius=10, **kwargs)
        self._build_ui()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Cabeçalho
        header = ctk.CTkFrame(self, fg_color=TacticalTheme.BG_CARD, corner_radius=8)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=14, pady=(14, 8))
        ctk.CTkLabel(
            header,
            text="[05] CAIXA DE FERRAMENTAS DE CRIPTOGRAFIA, HASHING & CODIFICAÇÃO",
            font=TacticalTheme.font(14, "bold"),
            text_color=TacticalTheme.ACCENT_CYAN,
        ).pack(anchor="w", padx=14, pady=(10, 2))
        ctk.CTkLabel(
            header,
            text="Conversão Base64/Hex/URL, geração de resumos criptográficos (MD5/SHA-256/SHA-512) e chaves CSPRNG.",
            font=TacticalTheme.font(11),
            text_color=TacticalTheme.TEXT_SECONDARY,
        ).pack(anchor="w", padx=14, pady=(0, 10))

        # Card Esquerdo: Codificação e Hashing
        left_card = ctk.CTkFrame(
            self,
            fg_color=TacticalTheme.BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        left_card.grid(row=1, column=0, sticky="nsew", padx=(14, 7), pady=6)
        left_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            left_card,
            text="ENTRADA DE DADOS (TEXTO / STRING)",
            font=TacticalTheme.font(12, "bold"),
            text_color=TacticalTheme.ACCENT_GREEN,
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        self.entry_input = ctk.CTkEntry(
            left_card,
            fg_color=TacticalTheme.BG_INPUT,
            font=TacticalTheme.font(11),
            placeholder_text="Digite o texto ou string codificada...",
        )
        self.entry_input.insert(0, "NetPulse-Tactical-Diagnostic-2026")
        self.entry_input.grid(row=1, column=0, sticky="ew", padx=12, pady=4)

        self.entry_hmac_key = ctk.CTkEntry(
            left_card,
            fg_color=TacticalTheme.BG_INPUT,
            font=TacticalTheme.font(11),
            placeholder_text="Chave secreta opcional para HMAC-SHA256...",
        )
        self.entry_hmac_key.grid(row=2, column=0, sticky="ew", padx=12, pady=4)

        btn_grid = ctk.CTkFrame(left_card, fg_color="transparent")
        btn_grid.grid(row=3, column=0, sticky="ew", padx=12, pady=(6, 12))
        btn_grid.grid_columnconfigure((0, 1, 2), weight=1)

        ctk.CTkButton(
            btn_grid,
            text="Gerar Hashes",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_CYAN,
            hover_color=TacticalTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            command=self._compute_hashes,
        ).grid(row=0, column=0, padx=3, pady=3, sticky="ew")

        ctk.CTkButton(
            btn_grid,
            text="Base64 Encode",
            font=TacticalTheme.font(11),
            fg_color=TacticalTheme.BG_INPUT,
            hover_color=TacticalTheme.ACCENT_DARK_BORDER,
            command=self._b64_encode,
        ).grid(row=0, column=1, padx=3, pady=3, sticky="ew")

        ctk.CTkButton(
            btn_grid,
            text="Base64 Decode",
            font=TacticalTheme.font(11),
            fg_color=TacticalTheme.BG_INPUT,
            hover_color=TacticalTheme.ACCENT_DARK_BORDER,
            command=self._b64_decode,
        ).grid(row=0, column=2, padx=3, pady=3, sticky="ew")

        ctk.CTkButton(
            btn_grid,
            text="Hex Encode",
            font=TacticalTheme.font(11),
            fg_color=TacticalTheme.BG_INPUT,
            hover_color=TacticalTheme.ACCENT_DARK_BORDER,
            command=self._hex_encode,
        ).grid(row=1, column=0, padx=3, pady=3, sticky="ew")

        ctk.CTkButton(
            btn_grid,
            text="Hex Decode",
            font=TacticalTheme.font(11),
            fg_color=TacticalTheme.BG_INPUT,
            hover_color=TacticalTheme.ACCENT_DARK_BORDER,
            command=self._hex_decode,
        ).grid(row=1, column=1, padx=3, pady=3, sticky="ew")

        ctk.CTkButton(
            btn_grid,
            text="URL Encode/Decode",
            font=TacticalTheme.font(11),
            fg_color=TacticalTheme.BG_INPUT,
            hover_color=TacticalTheme.ACCENT_DARK_BORDER,
            command=self._url_transform,
        ).grid(row=1, column=2, padx=3, pady=3, sticky="ew")

        # Card Direito: Gerador de Senhas / Chaves de Alta Entropia (CSPRNG)
        right_card = ctk.CTkFrame(
            self,
            fg_color=TacticalTheme.BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        right_card.grid(row=1, column=1, sticky="nsew", padx=(7, 14), pady=6)
        right_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            right_card,
            text="GERADOR DE CHAVES & SENHAS DE ALTA ENTROPIA",
            font=TacticalTheme.font(12, "bold"),
            text_color=TacticalTheme.ACCENT_CYAN,
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))

        self.lbl_len = ctk.CTkLabel(right_card, text="Comprimento (32 chars):", font=TacticalTheme.font(11))
        self.lbl_len.grid(row=1, column=0, sticky="w", padx=12, pady=4)

        self.slider_len = ctk.CTkSlider(
            right_card,
            from_=8,
            to=64,
            number_of_steps=56,
            button_color=TacticalTheme.ACCENT_GREEN,
            command=lambda v: self.lbl_len.configure(text=f"Comprimento ({int(v)} chars):"),
        )
        self.slider_len.set(32)
        self.slider_len.grid(row=1, column=1, sticky="ew", padx=12, pady=4)

        self.switch_symbols = ctk.CTkSwitch(
            right_card,
            text="Incluir Símbolos Especiais (!@#$%^&*)",
            font=TacticalTheme.font(11),
            progress_color=TacticalTheme.ACCENT_GREEN,
        )
        self.switch_symbols.select()
        self.switch_symbols.grid(row=2, column=0, columnspan=2, sticky="w", padx=12, pady=6)

        ctk.CTkButton(
            right_card,
            text="GERAR LOTE DE CHAVES SEGURAS (CSPRNG)",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_GREEN,
            hover_color=TacticalTheme.ACCENT_GREEN_HOVER,
            text_color="#000000",
            command=self._generate_keys,
        ).grid(row=3, column=0, columnspan=2, sticky="ew", padx=12, pady=(10, 12))

        # Console de Saída
        out_card = ctk.CTkFrame(self, fg_color=TacticalTheme.BG_CARD, corner_radius=8)
        out_card.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=14, pady=(6, 14))
        out_card.grid_rowconfigure(0, weight=1)
        out_card.grid_columnconfigure(0, weight=1)

        self.txt_out = ctk.CTkTextbox(
            out_card,
            fg_color=TacticalTheme.BG_TERMINAL,
            text_color=TacticalTheme.ACCENT_GREEN,
            font=TacticalTheme.font(11),
        )
        self.txt_out.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self._compute_hashes()

    def _write_output(self, title: str, body: str) -> None:
        self.txt_out.insert("end", f"\n=== {title} ===\n{body}\n")
        self.txt_out.see("end")

    def _compute_hashes(self) -> None:
        raw = self.entry_input.get()
        data = raw.encode("utf-8")
        md5_v = hashlib.md5(data).hexdigest()
        sha1_v = hashlib.sha1(data).hexdigest()
        sha256_v = hashlib.sha256(data).hexdigest()
        sha512_v = hashlib.sha512(data).hexdigest()

        lines = [
            f"Entrada ({len(data)} bytes): {raw}",
            f"MD5     : {md5_v}",
            f"SHA-1   : {sha1_v}",
            f"SHA-256 : {sha256_v}",
            f"SHA-512 : {sha512_v}",
        ]
        hmac_key = self.entry_hmac_key.get().strip()
        if hmac_key:
            digest = hmac.new(hmac_key.encode("utf-8"), data, hashlib.sha256).hexdigest()
            lines.append(f"HMAC-256: {digest}")

        self._write_output("RESUMOS CRIPTOGRÁFICOS", "\n".join(lines))

    def _b64_encode(self) -> None:
        raw = self.entry_input.get().encode("utf-8")
        encoded = base64.b64encode(raw).decode("ascii")
        self._write_output("BASE64 ENCODE", encoded)

    def _b64_decode(self) -> None:
        raw = self.entry_input.get().strip()
        try:
            decoded = base64.b64decode(raw, validate=False).decode("utf-8", errors="replace")
            self._write_output("BASE64 DECODE", decoded)
        except Exception as exc:
            self._write_output("ERRO BASE64 DECODE", str(exc))

    def _hex_encode(self) -> None:
        raw = self.entry_input.get().encode("utf-8")
        self._write_output("HEX ENCODE", raw.hex())

    def _hex_decode(self) -> None:
        raw = self.entry_input.get().strip().replace(" ", "")
        try:
            decoded = bytes.fromhex(raw).decode("utf-8", errors="replace")
            self._write_output("HEX DECODE", decoded)
        except Exception as exc:
            self._write_output("ERRO HEX DECODE", str(exc))

    def _url_transform(self) -> None:
        raw = self.entry_input.get()
        enc = urllib.parse.quote(raw, safe="")
        dec = urllib.parse.unquote(raw)
        self._write_output("URL ENCODE / DECODE", f"Encoded: {enc}\nDecoded: {dec}")

    def _generate_keys(self) -> None:
        length = int(self.slider_len.get())
        alphabet = string.ascii_letters + string.digits
        if self.switch_symbols.get():
            alphabet += "!@#$%^&*()-_=+[]{};:,.<>?"

        batch = ["".join(secrets.choice(alphabet) for _ in range(length)) for _ in range(5)]
        hex_token = secrets.token_hex(length // 2)
        body = "\n".join([f"Chave #{i+1}: {k}" for i, k in enumerate(batch)])
        body += f"\nToken Hex : {hex_token}"
        self._write_output(f"GERADOR CSPRNG ({length} CARACTERES)", body)
