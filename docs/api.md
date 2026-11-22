# Relay v2 API

All admin endpoints require `X-API-Key: <RELAY_ADMIN_API_KEY>` (or `Authorization: Bearer <key>`).

## Health
- `GET /health` - no auth, relay status + gateway summary

## VMs
- `GET /api/vms`
- `POST /api/vms`
  ```json
  {
    "name": "prod-web-01",
    "ip": "10.0.0.10",
    "ssh_port": 22,
    "username": "root",
    "password": "vm-password",
    "description": "optional",
    "enabled": true
  }
  ```
- `GET /api/vms/{vm_uid}`
- `PUT /api/vms/{vm_uid}` - same fields as POST, all optional
- `DELETE /api/vms/{vm_uid}`

VM response includes `vm_uid` and `ssh_command_example`. Client connects as:

```bash
ssh <target-user>-<vm_uid>@<relay-host> -p 22022
```

The SSH password is the VM's stored password.

## Gateways
- `GET /api/gateways`
- `POST /api/gateways`
  ```json
  {
    "name": "gw-seoul-1",
    "token": "optional-custom-token",
    "description": "optional",
    "enabled": true
  }
  ```
- `PUT /api/gateways/{name}`
- `DELETE /api/gateways/{name}`

Gateway runtime config:
- `GATEWAY_RELAY_WS_URL=ws://<relay-host>:18765/gateway`
- `GATEWAY_NAME=<name>`
- `GATEWAY_TOKEN=<token>`
