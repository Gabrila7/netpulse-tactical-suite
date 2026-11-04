# 🛡️ NetPulse // Tactical Network & System Diagnostic Suite

Aplicação desktop nativa e standalone desenvolvida em **Python + CustomTkinter** para administração avançada de redes, diagnóstico de conectividade, encaminhamento local de portas (TCP Port Forwarding de laboratório), validação de proxies SOCKS5/HTTP, auditoria de processos/sockets do sistema operacional e utilitários criptográficos.

---

## ✨ Características Principais

- **Interface Desktop Nativa (Frameless & Dark Tactical UI):** Janela própria sem bordas tradicionais (`overrideredirect`), barra de título customizada arrastável, estética em preto fosco/cinza chumbo (`#090b10` / `#11161f`) e acentos em ciano e verde neon.
- **Compatibilidade Multiplataforma (Windows & Linux):** Detecção automática de plataforma via `platform.system()` no módulo `core/system_platform.py`, adaptando flags de ICMP Ping, rastreamento de rota (`tracert` vs `tracepath`), opções de socket (`SO_REUSEADDR`/`SO_REUSEPORT`) e nitidez High-DPI.
- **Arquitetura 100% Modular:** Separação estrita entre configurações de tema (`core/theme.py`), abstrações de SO (`core/system_platform.py`) e as 5 abas operacionais em `views/`.

---

## 🗂️ Módulos do Painel

1. **Aba 1 — Túneis de Comunicação e Conectividade Avançada (`views/tunnel_view.py`):**
   - *TCP Port Forwarder Local:* Encaminhador assíncrono de tráfego TCP local para testes de serviços em laboratório.
   - *Benchmark de Latência TCP:* Medição precisa de RTT de handshakes TCP (`SYN/ACK`) com estatísticas de mínimo, média e máximo.
2. **Aba 2 — Diagnóstico de Rede e Portas (`views/scanner_view.py`):**
   - Inspeção multi-thread de portas TCP em ambientes de laboratório com identificação de serviço padrão IANA e leitura opcional de banner.
   - Execução integrada de ICMP Ping e verificação de rota nativa sem travar a interface gráfica.
3. **Aba 3 — Central de VPN, Servidor Proxy SOCKS5 & Roteamento (`views/routing_view.py`):**
   - **Sub-aba 🛡️ VPN & Adaptadores TUN/TAP:** Mapeamento automático de interfaces virtuais de VPN (`WireGuard`, `OpenVPN`, `Wintun`, `TAP`, `PPP`, `Tailscale`), conector de perfis `.ovpn` / `.conf` / `rasdial` / `nmcli`, gerador de perfis WireGuard (`.conf`) com chaves CSPRNG e detector de vazamento de IP/ISP/DNS (*VPN Leak Check*).
   - **Sub-aba 🌐 Servidor Proxy SOCKS5 & Pool:** Servidor Proxy SOCKS5 local integrado (`RFC 1928`) para tunelamento de aplicações locais, além de verificador multi-thread (*Health-Check*) de listas de proxies e rotação automática pelo menor ping.
   - **Sub-aba 🔍 Auditoria HTTP & DNS:** Teste de saída HTTP/HTTPS via Proxy ou rota direta, customização de cabeçalhos e resolução DNS (`A`, `AAAA` e reverso `PTR`).
4. **Aba 4 — Inspeção de Processos e Sockets do Sistema (`views/process_view.py`):**
   - Monitoramento em tempo real das conexões TCP e UDP abertas no sistema operacional correlacionadas com PID e nome do executável via `psutil`.
5. **Aba 5 — Caixa de Ferramentas de Criptografia e Codificação (`views/crypto_view.py`):**
   - Codificação/decodificação instantânea em **Base64**, **Hexadecimal** e **URL Encoding**.
   - Cálculo de hashes **MD5**, **SHA-1**, **SHA-256**, **SHA-512** e **HMAC-SHA256**.
   - Gerador criptograficamente seguro (`secrets` CSPRNG) de chaves e senhas de alta entropia.

---

## 📁 Estrutura de Diretórios

```text
netpulse-tactical-suite/
├── .gitignore
├── README.md
├── requirements.txt
├── main.py
├── core/
│   ├── __init__.py
│   ├── theme.py
│   └── system_platform.py
└── views/
    ├── __init__.py
    ├── tunnel_view.py
    ├── scanner_view.py
    ├── routing_view.py
    ├── process_view.py
    └── crypto_view.py
```

---

## 🚀 Instalação e Execução em Desenvolvimento

### 1. Criar e ativar o ambiente virtual

**No Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**No Linux (Bash):**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Instalar as dependências
```bash
pip install -r requirements.txt
```

### 3. Executar a aplicação
```bash
python main.py
```

---

## 📦 Como Gerar o Executável Nativo (PyInstaller)

Para compilar a aplicação em um binário standalone nativo sem janela de terminal em segundo plano (`--noconsole` / `--windowed`) e incluindo os ativos do CustomTkinter:

**No Windows:**
```powershell
pyinstaller --noconfirm --onedir --windowed --name "NetPulseTactical" --collect-all customtkinter main.py
```
O executável final estará disponível em `dist/NetPulseTactical/NetPulseTactical.exe` (ou utilize `--onefile` para gerar um único arquivo `.exe`).

**No Linux:**
```bash
pyinstaller --noconfirm --onedir --windowed --name "NetPulseTactical" --collect-all customtkinter main.py
```
O binário nativo estará disponível em `dist/NetPulseTactical/NetPulseTactical`.

---

## ⚖️ Aviso Legal e Uso Ético

Este software foi projetado exclusivamente para **administração de sistemas, diagnóstico de infraestrutura de rede, testes de conectividade em laboratório e auditoria de máquinas próprias ou formalmente autorizadas**.
