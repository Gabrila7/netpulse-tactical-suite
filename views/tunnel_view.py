"""
Aba 1: Túneis de Comunicação e Conectividade Avançada.
Fornece um encaminhador (Port Forwarder / TCP Relay) local para testes de laboratório,
além de medidor de latência de handshake TCP em tempo real e console de logs de sockets.
"""

import datetime
import select
import socket
import threading
import time
import customtkinter as ctk
from core.theme import TacticalTheme
from core.system_platform import SystemPlatform


class TunnelView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=TacticalTheme.BG_PANEL, corner_radius=10, **kwargs)
        self.relay_running = False
        self.relay_server_socket = None
        self.bytes_forwarded = 0
        self.active_sessions = 0
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
            text="[01] TÚNEIS DE COMUNICAÇÃO & TELEMETRIA DE CONECTIVIDADE TCP",
            font=TacticalTheme.font(14, "bold"),
            text_color=TacticalTheme.ACCENT_CYAN,
        ).pack(anchor="w", padx=14, pady=(10, 2))
        ctk.CTkLabel(
            header,
            text="Encaminhamento de portas TCP locais (Port Forwarder de laboratório) e diagnóstico de handshake.",
            font=TacticalTheme.font(11),
            text_color=TacticalTheme.TEXT_SECONDARY,
        ).pack(anchor="w", padx=14, pady=(0, 10))

        # Card Esquerdo: TCP Port Forwarder / Relay Local
        relay_card = ctk.CTkFrame(
            self,
            fg_color=TacticalTheme.BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        relay_card.grid(row=1, column=0, sticky="nsew", padx=(14, 7), pady=6)

        ctk.CTkLabel(
            relay_card,
            text="TCP PORT FORWARDER (TÚNEL LOCAL)",
            font=TacticalTheme.font(12, "bold"),
            text_color=TacticalTheme.ACCENT_GREEN,
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))

        ctk.CTkLabel(relay_card, text="Bind Local (IP:Porta):", font=TacticalTheme.font(11)).grid(
            row=1, column=0, sticky="w", padx=12, pady=4
        )
        self.entry_listen = ctk.CTkEntry(
            relay_card,
            fg_color=TacticalTheme.BG_INPUT,
            font=TacticalTheme.font(11),
            width=180,
        )
        self.entry_listen.insert(0, "127.0.0.1:8888")
        self.entry_listen.grid(row=1, column=1, sticky="ew", padx=12, pady=4)

        ctk.CTkLabel(relay_card, text="Destino Remoto (Host:Porta):", font=TacticalTheme.font(11)).grid(
            row=2, column=0, sticky="w", padx=12, pady=4
        )
        self.entry_target = ctk.CTkEntry(
            relay_card,
            fg_color=TacticalTheme.BG_INPUT,
            font=TacticalTheme.font(11),
            width=180,
        )
        self.entry_target.insert(0, "example.com:80")
        self.entry_target.grid(row=2, column=1, sticky="ew", padx=12, pady=4)

        ctk.CTkLabel(relay_card, text="Buffer de Pacote (KB):", font=TacticalTheme.font(11)).grid(
            row=3, column=0, sticky="w", padx=12, pady=4
        )
        self.slider_buffer = ctk.CTkSlider(
            relay_card,
            from_=1,
            to=64,
            number_of_steps=63,
            button_color=TacticalTheme.ACCENT_CYAN,
            progress_color=TacticalTheme.ACCENT_CYAN_HOVER,
        )
        self.slider_buffer.set(8)
        self.slider_buffer.grid(row=3, column=1, sticky="ew", padx=12, pady=4)

        self.switch_Relay = ctk.CTkSwitch(
            relay_card,
            text="Ativar Túnel TCP Local",
            font=TacticalTheme.font(11, "bold"),
            progress_color=TacticalTheme.ACCENT_GREEN,
            command=self._toggle_relay,
        )
        self.switch_Relay.grid(row=4, column=0, columnspan=2, sticky="w", padx=12, pady=(8, 12))

        # Card Direito: Teste de Latência TCP Handshake
        probe_card = ctk.CTkFrame(
            self,
            fg_color=TacticalTheme.BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=TacticalTheme.ACCENT_DARK_BORDER,
        )
        probe_card.grid(row=1, column=1, sticky="nsew", padx=(7, 14), pady=6)

        ctk.CTkLabel(
            probe_card,
            text="BENCHMARK DE LATÊNCIA TCP (SYN/ACK)",
            font=TacticalTheme.font(12, "bold"),
            text_color=TacticalTheme.ACCENT_CYAN,
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))

        ctk.CTkLabel(probe_card, text="Endpoint Alvo (Host:Porta):", font=TacticalTheme.font(11)).grid(
            row=1, column=0, sticky="w", padx=12, pady=4
        )
        self.entry_probe_host = ctk.CTkEntry(
            probe_card,
            fg_color=TacticalTheme.BG_INPUT,
            font=TacticalTheme.font(11),
            width=180,
        )
        self.entry_probe_host.insert(0, "1.1.1.1:443")
        self.entry_probe_host.grid(row=1, column=1, sticky="ew", padx=12, pady=4)

        ctk.CTkLabel(probe_card, text="Amostras (Pacotes):", font=TacticalTheme.font(11)).grid(
            row=2, column=0, sticky="w", padx=12, pady=4
        )
        self.slider_samples = ctk.CTkSlider(
            probe_card,
            from_=1,
            to=20,
            number_of_steps=19,
            button_color=TacticalTheme.ACCENT_GREEN,
            progress_color=TacticalTheme.ACCENT_GREEN_HOVER,
        )
        self.slider_samples.set(5)
        self.slider_samples.grid(row=2, column=1, sticky="ew", padx=12, pady=4)

        self.btn_probe = ctk.CTkButton(
            probe_card,
            text="EXECUTAR TESTE DE LATÊNCIA TCP",
            font=TacticalTheme.font(11, "bold"),
            fg_color=TacticalTheme.ACCENT_CYAN,
            hover_color=TacticalTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            command=self._start_tcp_probe,
        )
        self.btn_probe.grid(row=3, column=0, columnspan=2, sticky="ew", padx=12, pady=(10, 6))

        self.lbl_metrics = ctk.CTkLabel(
            probe_card,
            text="Sessões Ativas: 0 | Tráfego Encaminhado: 0 B",
            font=TacticalTheme.font(11),
            text_color=TacticalTheme.ACCENT_AMBER,
        )
        self.lbl_metrics.grid(row=4, column=0, columnspan=2, sticky="w", padx=12, pady=(2, 10))

        # Terminal de Logs de Sockets em Tempo Real
        log_frame = ctk.CTkFrame(self, fg_color=TacticalTheme.BG_CARD, corner_radius=8)
        log_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=14, pady=(6, 14))
        log_frame.grid_rowconfigure(1, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        top_bar = ctk.CTkFrame(log_frame, fg_color="transparent")
        top_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 4))
        ctk.CTkLabel(
            top_bar,
            text="TERMINAL DE TELEMETRIA DE SOCKETS EM TEMPO REAL",
            font=TacticalTheme.font(11, "bold"),
            text_color=TacticalTheme.TEXT_SECONDARY,
        ).pack(side="left")

        ctk.CTkButton(
            top_bar,
            text="Limpar Log",
            width=90,
            height=24,
            font=TacticalTheme.font(10),
            fg_color=TacticalTheme.BG_INPUT,
            hover_color=TacticalTheme.ACCENT_DARK_BORDER,
            command=self._clear_log,
        ).pack(side="right")

        self.txt_log = ctk.CTkTextbox(
            log_frame,
            fg_color=TacticalTheme.BG_TERMINAL,
            text_color=TacticalTheme.ACCENT_GREEN,
            font=TacticalTheme.font(11),
            corner_radius=6,
        )
        self.txt_log.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._log(f"Console de Conectividade inicializado [{SystemPlatform.get_system_summary()}]")

    def _log(self, msg: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.txt_log.insert("end", f"[{ts}] {msg}\n")
        self.txt_log.see("end")

    def _clear_log(self) -> None:
        self.txt_log.delete("1.0", "end")

    def _update_metrics(self) -> None:
        self.lbl_metrics.configure(
            text=f"Sessões Ativas: {self.active_sessions} | Tráfego Encaminhado: {self.bytes_forwarded} B"
        )

    def _toggle_relay(self) -> None:
        if self.switch_Relay.get() == 1:
            self._start_relay()
        else:
            self._stop_relay()

    def _start_relay(self) -> None:
        try:
            listen_str = self.entry_listen.get().strip()
            target_str = self.entry_target.get().strip()
            l_host, l_port_s = listen_str.split(":")
            t_host, t_port_s = target_str.split(":")
            l_port, t_port = int(l_port_s), int(t_port_s)
        except ValueError:
            self._log("[ERRO] Formato inválido. Utilize HOST:PORTA (ex: 127.0.0.1:8888).")
            self.switch_Relay.deselect()
            return

        buf_size = int(self.slider_buffer.get()) * 1024
        self.relay_running = True
        threading.Thread(
            target=self._relay_loop,
            args=(l_host, l_port, t_host, t_port, buf_size),
            daemon=True,
        ).start()

    def _stop_relay(self) -> None:
        self.relay_running = False
        if self.relay_server_socket:
            try:
                self.relay_server_socket.close()
            except Exception:
                pass
        self._log("[INFO] Túnel TCP local encerrado pelo operador.")

    def _relay_loop(self, l_host: str, l_port: int, t_host: str, t_port: int, buf_size: int) -> None:
        try:
            srv = SystemPlatform.create_configured_socket(timeout=1.0)
            srv.bind((l_host, l_port))
            srv.listen(5)
            self.relay_server_socket = srv
            self.after(0, lambda: self._log(
                f"[TÚNEL ATIVO] Escutando em {l_host}:{l_port} -> Encaminhando para {t_host}:{t_port} (Buffer: {buf_size} B)"
            ))

            while self.relay_running:
                try:
                    client_sock, addr = srv.accept()
                    self.active_sessions += 1
                    self.after(0, self._update_metrics)
                    self.after(0, lambda a=addr: self._log(f"[CONEXÃO] Cliente conectado de {a[0]}:{a[1]}"))
                    threading.Thread(
                        target=self._handle_tunnel_client,
                        args=(client_sock, t_host, t_port, buf_size),
                        daemon=True,
                    ).start()
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception as exc:
            self.after(0, lambda e=exc: self._log(f"[FALHA NO BIND] {e}"))
            self.after(0, self.switch_Relay.deselect)
            self.relay_running = False

    def _handle_tunnel_client(self, client_sock: socket.socket, t_host: str, t_port: int, buf_size: int) -> None:
        remote_sock = None
        try:
            remote_sock = SystemPlatform.create_configured_socket(timeout=5.0)
            remote_sock.connect((t_host, t_port))
            sockets = [client_sock, remote_sock]
            while self.relay_running:
                readable, _, _ = select.select(sockets, [], [], 1.0)
                if not readable:
                    continue
                for s in readable:
                    data = s.recv(buf_size)
                    if not data:
                        return
                    target = remote_sock if s is client_sock else client_sock
                    target.sendall(data)
                    self.bytes_forwarded += len(data)
                    self.after(0, self._update_metrics)
        except Exception as exc:
            self.after(0, lambda e=exc: self._log(f"[SESSÃO ENCERRADA] {e}"))
        finally:
            for s in (client_sock, remote_sock):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
            self.active_sessions = max(0, self.active_sessions - 1)
            self.after(0, self._update_metrics)

    def _start_tcp_probe(self) -> None:
        target = self.entry_probe_host.get().strip()
        samples = int(self.slider_samples.get())
        self.btn_probe.configure(state="disabled")
        threading.Thread(target=self._probe_worker, args=(target, samples), daemon=True).start()

    def _probe_worker(self, target: str, samples: int) -> None:
        try:
            host, port_s = target.split(":")
            port = int(port_s)
        except ValueError:
            self.after(0, lambda: self._log("[ERRO] Endpoint inválido. Use HOST:PORTA (ex: 1.1.1.1:443)."))
            self.after(0, lambda: self.btn_probe.configure(state="normal"))
            return

        self.after(0, lambda: self._log(f"[SONDA TCP] Iniciando {samples} handshakes para {host}:{port}..."))
        rtts = []
        for idx in range(1, samples + 1):
            sock = SystemPlatform.create_configured_socket(timeout=3.0)
            start = time.perf_counter()
            try:
                sock.connect((host, port))
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                rtts.append(elapsed_ms)
                self.after(
                    0,
                    lambda i=idx, ms=elapsed_ms: self._log(
                        f"  -> Amostra #{i}/{samples}: Handshake TCP concluído em {ms:.2f} ms"
                    ),
                )
            except Exception as exc:
                self.after(0, lambda i=idx, e=exc: self._log(f"  -> Amostra #{i}/{samples}: Falha ({e})"))
            finally:
                sock.close()
            time.sleep(0.2)

        if rtts:
            avg_ms = sum(rtts) / len(rtts)
            min_ms = min(rtts)
            max_ms = max(rtts)
            self.after(
                0,
                lambda: self._log(
                    f"[RESUMO TCP] Sucesso: {len(rtts)}/{samples} | Mín: {min_ms:.2f}ms | Méd: {avg_ms:.2f}ms | Máx: {max_ms:.2f}ms"
                ),
            )
        self.after(0, lambda: self.btn_probe.configure(state="normal"))
