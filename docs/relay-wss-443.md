# Althera Remote — relay por WSS na porta 443 (abrir em qualquer rede)

Objetivo: o Althera Remote conectar em **qualquer rede de cliente**, inclusive as que bloqueiam
as portas próprias do RustDesk (21116/21117). Solução: tudo passa por **WebSocket seguro (wss)
na porta 443**, via relay — indistinguível de HTTPS normal para o firewall do cliente.

## O que mudou no cliente (já aplicado no código)

- `libs/hbb_common/src/config.rs` — `RENDEZVOUS_SERVERS = ["suporte.altheratech.com.br"]`
  (hostname, não IP: só com domínio o cliente monta `wss://host:443/ws/...`).
- `src/common.rs` → `load_custom_client()` — defaults de fábrica:
  `allow-websocket=Y`, `api-server=https://suporte.altheratech.com.br`,
  `websocket-port=443`, `force-always-relay=Y`.

Com isso o cliente liga em `wss://suporte.altheratech.com.br:443/ws/id` (rendezvous) e
`.../ws/relay` (relay). Tudo via relay ⇒ sem depender de furo de NAT por UDP (o mais bloqueado).

## O que falta na VPS1 (rodar você, no PROMPT do Claude Code com `!`)

### 1. Confirmar que hbbs/hbbr expõem WebSocket (21118/21119)

```bash
ss -lntp | grep -E '2111[89]'      # espera-se hbbs:21118 e hbbr:21119 escutando
```
rustdesk-server ≥ 1.1.10 já escuta ws nessas portas por padrão. Se não aparecer, subir hbbs/hbbr
com as portas ws abertas (só em 127.0.0.1 basta — o nginx fala com elas localmente).

### 2. Adicionar as duas rotas ao vhost `suporte.altheratech.com.br` (porta 443)

No server block TLS que já serve `suporte.altheratech.com.br`, adicionar:

```nginx
    # --- Althera Remote (RustDesk) relay por WSS/443 ---
    location /ws/id {
        proxy_pass http://127.0.0.1:21118;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
    location /ws/relay {
        proxy_pass http://127.0.0.1:21119;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
```

Não conflita com as rotas existentes (`/`, `/diag/...`). Depois:

```bash
nginx -t && systemctl reload nginx
```

### 3. Testar o handshake wss (de fora da VPS, de preferência)

```bash
curl -sSI -o /dev/null -w '%{http_code}\n' \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGVzdA==' \
  https://suporte.altheratech.com.br/ws/id
# 101 = upgrade OK (ou 400/426 vindo do hbbs = chegou no backend; 404 = location não aplicou)
```

## Como validar de ponta a ponta

1. Buildar o fork (CI nightly) e instalar o `AltheraRemote.exe` novo numa máquina de TESTE
   (NÃO a da Karol — produção, PII de cliente).
2. Numa rede que antes NÃO conectava, confirmar que conecta.
3. Nos logs do cliente deve aparecer conexão a `wss://suporte.altheratech.com.br:443/ws/...`.

## Trade-offs (ciente)

- **Tudo passa por relay/VPS1** ⇒ um pouco mais de latência e todo o tráfego consome banda da VPS1.
  É o preço de "abrir em qualquer rede". Para um caso específico de LAN, dá pra desligar com
  `allow-websocket=""` num `custom.txt` ao lado do exe.
- `api-server=https://...` é setado só para o cliente escolher `wss`. Login/catálogo (address book)
  da API não são usados pela Althera (conexão é por ID+senha + o gateway de suporte).
