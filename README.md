# Nomi Auth

SQLite 账号与 Yggdrasil 服务，供 Nomi 启动器与 QQ 官方机器人使用。

## 开发启动

需要 Python 3.12 或 3.13 和 uv。

```powershell
uv sync
Copy-Item .env.example .env
# 配置 .env 中的机器人应用 ID、指定群 OpenID、服务凭证和公开地址。
uv run uvicorn nomi_auth.app:create_app --factory --host 127.0.0.1 --port 8000 --workers 1
```

接口文档 `/docs`，健康检查 `/health`，Yggdrasil 根路径 `/api/yggdrasil`。生产公开地址使用 HTTPS，与启动器配置保持一致。机器人使用同一服务凭证、应用 ID 和群 OpenID。

已实现单码注册、身份唯一性、Yggdrasil 会话、管理登录、PNG 皮肤、固定 UUID 改名、密码修改和群验证找回。登录名固定，游戏名可修改，密码至少 10 位。管理令牌默认有效一小时，到期重新登录；管理刷新令牌尚未提供。游戏令牌可通过协议 refresh 刷新。

SQLite、纹理和首次生成的 RSA 签名私钥位于 `NOMI_DATA_DIR`，重启复用。此目录不能公开或提交 Git。

## 验证与维护

```text
uv run pytest -q
uv run ruff check src tests
uv run python -m nomi_auth.cli backup backups/nomi-2026-10-12.sqlite3
uv run python -m nomi_auth.cli cleanup
uv run python -m nomi_auth.cli disable Alice
uv run python -m nomi_auth.cli enable Alice
```

备份命令只生成数据库快照，还需备份纹理与签名密钥。cleanup 应每日运行。停用会撤销会话，已在线玩家需由游戏服管理员踢出。`deploy/` 提供 systemd 和可选 Nginx 示例，无需 Docker。

直接部署时创建 `nomi` 服务用户，将应用与虚拟环境放到 `/opt/nomi-auth`，创建归该用户所有的 `/var/lib/nomi-auth`。复制 `deploy/service.env.example` 到 `/etc/nomi-auth/service.env` 并填写真实值，配置文件权限设为 `0600`。复制 service 文件到 systemd 后再启用服务。Nginx 示例中配置实际域名与证书；后端仅监听回环地址，信任来源只限回环代理。远程机器人应使用私网或单独允许的内部路由。

工作区内首次开发配置可执行 `uv run python -m nomi_auth.setup_local --bot-dir ../nomi-bot`。命令不会覆盖既有 Nomi 配置；指定群未知时启用机器人本地查询模式并禁用注册。填写群 ID 后关闭查询模式，重启两个服务。

当前使用标准库 sqlite3 和 schema 版本 1，后续结构变更需要显式迁移。已通过的 API 测试不能替代真实 QQ 群事件和 Minecraft 进服联调。
