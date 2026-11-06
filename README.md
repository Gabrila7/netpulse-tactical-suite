# NetPulse Tactical Suite

Aplicação desktop em Python com interface gráfica feita em CustomTkinter para diagnóstico de redes, testes de latência, gerenciamento de conexões/VPN e monitoramento de sockets locais.

O projeto foi construído de forma modular para reunir em um painel único utilitários frequentes de laboratório de redes e análise de conexões do sistema operacional.

---

## Módulos do Sistema

1. **Túneis & Conectividade (`views/tunnel_view.py`):**
   - **TCP Port Forwarder:** cria um relay TCP local para redirecionar tráfego de uma porta local para um host remoto.
   - **Benchmark de Handshake TCP:** mede tempos de resposta (RTT) de conexões TCP consecutivas calculando latência mínima, média e máxima.

2. **Diagnóstico de Portas & Rotas (`views/scanner_view.py`):**
   - Varredura concorrente de portas TCP (usando `ThreadPoolExecutor`) com identificação do serviço associado (IANA) e captura opcional de banner.
   - Atalhos para execução nativa de Ping ICMP e rastreamento de rota (Traceroute/Tracepath) sem congelar a janela.

3. **VPN & Proxy Suite (`views/routing_view.py`):**
   - **VPN & Adaptadores:** mapeia adaptadores virtuais de rede (`WireGuard`, `OpenVPN`, `TUN/TAP`, `Tailscale`), permite conectar perfis e realizar testes de vazamento de IP/DNS.
   - **Servidor Proxy SOCKS5 Local:** implementação do protocolo SOCKS5 (RFC 1928) para rodar um proxy local na máquina (`127.0.0.1:1080`).
   - **Health-Check de Proxies:** testa conectividade e latência de listas de proxies externos, com rotação automática pelo menor ping.
   - **Auditoria de Saída & DNS:** testes de requisições HTTP passando pelo proxy e resolução detalhada de registros DNS (IPv4/IPv6 e reverso).

4. **Processos & Sockets (`views/process_view.py`):**
   - Inspeção de conexões TCP/UDP ativas na máquina via biblioteca `psutil`, associando cada socket ao seu respectivo PID e nome de processo do sistema.

5. **Criptografia & Codificação (`views/crypto_view.py`):**
   - Utilitário local para codificação e decodificação em Base64, Hexadecimal e URL.
   - Cálculo de resumos criptográficos (MD5, SHA-1, SHA-256, SHA-512 e HMAC-SHA256).
   - Gerador de chaves e senhas aleatórias utilizando o módulo seguro `secrets` (CSPRNG).

---

## Estrutura do Código

```text
netpulse-tactical-suite/
├── main.py                    # Inicialização da interface, janela customizada e barra de telemetria
├── core/
│   ├── theme.py               # Paleta de cores escura e tipografia
│   └── system_platform.py     # Detecção do SO (Windows/Linux), chamadas de sistema e sockets
└── views/
    ├── tunnel_view.py         # Aba 1: túneis TCP e testes de latência
    ├── scanner_view.py        # Aba 2: inspeção de portas e rotas
    ├── routing_view.py        # Aba 3: VPN, servidor SOCKS5 e proxies
    ├── process_view.py        # Aba 4: mapeamento de conexões e processos
    └── crypto_view.py         # Aba 5: ferramentas de hash e codificação
```

---

## Instalação e Execução

### 1. Criar ambiente virtual

No Windows:
```cmd
python -m venv .venv
.venv\Scripts\activate
```

No Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Instalar dependências
```bash
pip install -r requirements.txt
```

### 3. Rodar o programa
```bash
python main.py
```

---

## Gerar Executável (.exe)

O projeto pode ser compilado em um executável único via PyInstaller com o comando:

```cmd
pyinstaller --noconfirm --onefile --windowed --name "NetPulseTactical" --collect-all customtkinter main.py
```
O arquivo gerado ficará na pasta `dist/NetPulseTactical.exe`.

---

## Autor

Gabriel Vinícius  
GitHub: [@Gabrila7](https://github.com/Gabrila7)
