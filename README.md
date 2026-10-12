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

当前使用标准库 sqlite3 和 schema 版本 1，后续结构变更需要显式迁移。已通过的 API 测试不能替代真实 QQ 群事件和 Minecraft 进服联调。
