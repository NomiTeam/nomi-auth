# Nomi Auth

SQLite 账号与 Yggdrasil 服务。注册和登录均通过指定 QQ 群验证码，不收集、保存或校验用户密码。

## 本地运行

需要 Python 3.12 或 3.13 和 uv。在本目录执行：

```text
uv sync
uv run uvicorn nomi_auth.app:create_app --factory --host 127.0.0.1 --port 8000 --workers 1
```

首次配置复制 `.env.example` 为 `.env`，或在同一工作区执行 `uv run python -m nomi_auth.setup_local --bot-dir ../nomi-bot`。配置双方相同的机器人应用、群 OpenID 和服务凭证。接口文档 `/docs`，健康检查 `/health`，认证根路径 `/api/yggdrasil/`。生产公开地址必须使用 HTTPS。

## 群验证码认证

- 注册：`POST /api/v1/registrations` 只提交 `name`，在群内发送 `注册 <码>`。第一位成功兑换的有效群成员完成绑定，每个成员只允许一个账号。
- 已有账号或重装启动器：`POST /api/v1/logins` 提交固定 `username`，在群内发送 `登录 <码>`。仅账号绑定的成员能验证，其他成员不能消费申请。
- 启动器用申请私密 `poll_token` 查询状态，再向 `/api/v1/logins/{id}/session` 或 `/api/v1/registrations/{id}/session` 单次领取管理与游戏令牌。公开群码不能查询私有状态或领取令牌。
- 申请默认 5 分钟有效，验证码验证和会话领取分别只能成功一次。领取响应丢失时重新发起验证码登录，不重复发放凭据。
- 游戏令牌支持标准 refresh、validate、invalidate 和进服会话。传统 authenticate 和 signout 不接受密码，返回群验证登录提示。

固定登录名不随游戏名改变；修改游戏名时 UUID 不变。管理会话默认一小时，到期通过群验证码重新登录。没有密码修改或密码找回接口。

## 数据与维护

SQLite schema 版本 2 会自动移除旧密码字段、撤销旧会话，保留账号、群身份与 UUID。升级前先使用 SQLite backup API 做备份。签名密钥与纹理位于 `NOMI_DATA_DIR`，服务重启复用，不得公开或提交这些文件。

```text
uv run pytest -q
uv run ruff check src tests
uv run python -m nomi_auth.cli backup backups/nomi.sqlite3
uv run python -m nomi_auth.cli cleanup
uv run python -m nomi_auth.cli disable Alice
uv run python -m nomi_auth.cli enable Alice
```

备份数据库时同时备份纹理与签名私钥。cleanup 每日执行。停用账号保留群绑定并撤销令牌，已在线玩家由游戏服管理员另行踢出。

`deploy/` 提供 systemd、环境配置和可选 Nginx 示例，无需 Docker。应用与虚拟环境置于 `/opt/nomi-auth`，服务用户拥有 `/var/lib/nomi-auth`；真实配置放在 `/etc/nomi-auth/service.env`，权限 0600。配置真实 HTTPS 公共地址、证书和内部机器人访问策略。
