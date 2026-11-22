# xquare-ct-relay-v2

SSH relay v2: client SSHes into relay, relay routes over WebSocket to internal gateways, gateways SSH into target VMs inside private network.

## Architecture

```text
Client
  | ssh <target-user>-<vm_uid>@relay:22022
Relay (public)
  | websocket /gateway (ws://relay:18765/gateway)
Gateway (internal, multiple allowed, load-balanced)
  | ssh (password)
Target VM (internal)
```

## Relay 설치

릴레이는 공개망에 배치하며, 클라이언트 SSH 수신, 게이트웨이 WS 수신, 관리 API/UI, SQLite 저장을 담당합니다.

### 1) Docker로 설치

```bash
git clone https://github.com/team-xquare/xquare-ct-relay-v2.git
cd xquare-ct-relay-v2
cp .env.example .env
```

`.env` 설정:

```env
RELAY_ADMIN_API_KEY=<강력한-랜덤-키>
```

실행:

```bash
docker compose up -d --build relay
```

확인:

```bash
curl http://localhost:18080/health
```

- 관리 UI: `http://<relay-host>:18080`
- 클라이언트 SSH 포트: `22022`
- 게이트웨이 WS 포트: `18765`
- 데이터: Docker volume `relay-data` (`/data/relay.db`, `/data/relay_host_key`)

### 2) Python으로 직접 실행

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r relay/requirements.txt
RELAY_ADMIN_API_KEY=<강력한-랜덤-키> python -m relay.app.main -c relay/config.example.yaml
```

또는 환경변수로 설정:

```bash
export RELAY_ADMIN_API_KEY=<강력한-랜덤-키>
export RELAY_SSH_PORT=22022
export RELAY_WS_PORT=18765
export RELAY_HTTP_PORT=18080
export RELAY_DB_PATH=./data/relay.db
export RELAY_HOST_KEY=./data/relay_host_key
python -m relay.app.main
```

### Relay 운영 포인트

- `RELAY_ADMIN_API_KEY`는 반드시 설정. 없으면 관리 API가 동작하지 않습니다.
- 방화벽/보안그룹: `22022`(SSH), `18765`(Gateway WS), `18080`(Admin HTTP) 필요. `18080`은 내부망/VPN/리버스프록시로 제한 권장.
- 프로덕션에서는 HTTP/WS를 TLS 뒤에 배치하세요.

## Gateway 설치

게이트웨이는 내부망에 배치하며, 릴레이로 outbound WebSocket 연결을 맺고 내부 VM에 SSH로 접속합니다. **대상 VM에 에이전트 설치는 필요 없습니다.**

### 1) 릴레이에 게이트웨이 등록

릴레이 UI(`http://<relay-host>:18080`) 또는 API로 게이트웨이를 먼저 등록하고 토큰을 발급받습니다.

```bash
curl -X POST http://<relay-host>:18080/api/gateways \
  -H "X-API-Key: <RELAY_ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"name":"gw-seoul-1","description":"seoul internal gateway"}'
```

응답의 `token` 값을 게이트웨이 설정에 사용합니다.

### 2) Docker로 설치

같은 레포에서 실행:

```bash
cp .env.example .env
# .env에 GATEWAY_NAME, GATEWAY_TOKEN 설정
docker compose up -d --build gateway
```

별도 호스트에서 단독 실행:

```bash
docker build -t xquare-ct-gateway ./gateway
docker run -d --name xquare-ct-gateway --restart unless-stopped \
  -e GATEWAY_RELAY_WS_URL=ws://<relay-host>:18765/gateway \
  -e GATEWAY_NAME=gw-seoul-1 \
  -e GATEWAY_TOKEN=<등록된-토큰> \
  xquare-ct-gateway
```

### 3) Python으로 직접 실행

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r gateway/requirements.txt

export GATEWAY_RELAY_WS_URL=ws://<relay-host>:18765/gateway
export GATEWAY_NAME=gw-seoul-1
export GATEWAY_TOKEN=<등록된-토큰>
python -m gateway.app.main
```

### Gateway 운영 포인트

- 게이트웨이는 릴레이로 **outbound** 연결만 합니다. 릴레이의 `18765`에 접근 가능하면 됩니다.
- 게이트웨이는 대상 VM의 SSH 포트(기본 22)에 내부망에서 접근 가능해야 합니다.
- 게이트웨이는 여러 개 등록/실행 가능하며, 릴레이가 새 SSH 세션을 라운드로빈으로 분배합니다.
- 릴레이 UI/API에서 게이트웨이 `online/sessions` 상태를 확인할 수 있습니다.

## VM 등록 및 접속

릴레이 UI 또는 API로 VM을 등록합니다.

```bash
curl -X POST http://<relay-host>:18080/api/vms \
  -H "X-API-Key: <RELAY_ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-web-01",
    "ip": "10.0.0.10",
    "ssh_port": 22,
    "username": "root",
    "password": "<vm-password>",
    "description": "production web"
  }'
```

응답의 `vm_uid`를 사용해 접속:

```bash
ssh <target-user>-<vm_uid>@<relay-host> -p 22022
```

- SSH 비밀번호는 VM 등록 시 저장한 비밀번호입니다.
- `<target-user>`는 접속하려는 VM의 OS 사용자 이름입니다(예: `root`, `ubuntu`).

## 설정 요약

### Relay env
- `RELAY_ADMIN_API_KEY` - 관리 API 키 (필수)
- `RELAY_SSH_PORT` - 기본 `22022`
- `RELAY_WS_PORT` - 기본 `18765`
- `RELAY_HTTP_PORT` - 기본 `18080`
- `RELAY_DB_PATH` - 기본 `/data/relay.db`
- `RELAY_HOST_KEY` - 기본 `/data/relay_host_key`

### Gateway env
- `GATEWAY_RELAY_WS_URL` - 예: `ws://relay-host:18765/gateway`
- `GATEWAY_NAME` - 릴레이에 등록한 이름
- `GATEWAY_TOKEN` - 릴레이에서 발급된 토큰

## 참고

- VM 비밀번호는 릴레이 SQLite에 저장됩니다. `/data`, API 키, 관리자 UI 접근을 보호하세요.
- 로드밸런싱은 온라인 게이트웨이 대상 라운드로빈(세션 단위)입니다.
- 프로덕션에서는 TLS 리버스프록시, 네트워크 ACL, 비밀 관리 적용을 권장합니다.
- 상세 API: [`docs/api.md`](docs/api.md)
