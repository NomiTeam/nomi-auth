# Nomi Auth

FastAPI + SQLite 的单群账号与 Yggdrasil 服务，供 Nomi 启动器和 QQ 插件使用，不存储用户密码。

## 本地运行

需要 Python 3.12/3.13 和 uv。复制 `.env.example` 为 `.env`，填写机器人应用 ID、群 OpenID 和与插件一致的服务凭证，再执行：

```text
uv sync
uv run uvicorn nomi_auth.app:create_app --factory --host 127.0.0.1 --port 8000 --workers 1
```

接口文档 `/docs`，健康检查 `/health`，认证根路径 `/api/yggdrasil/`。公网地址使用 HTTPS。

## 账号与数据

统一申请登录码：已有账号直接登录，未注册成员在群内提交 `注册 <id>`。申请有效期默认 5 分钟，每次验证只签发一组会话。支持本人改名和 HMCL 原生皮肤上传；改名默认冷却 7 天，UUID 不变。

游戏令牌默认 24 小时，管理令牌 1 小时；启动器另持有 30 天刷新令牌，使用时单次轮换并重新计算 30 天有效期。登录领取和续期支持同一请求在两分钟内重试，返回原凭据且不延长有效期；重试记录只存哈希和随机值，过期自动清理。刷新接口只接受刷新令牌，停用账号会撤销所有令牌。旧账户需重新群验证一次领取刷新令牌。

领取或取消后立即删除申请，失败结果经私密查询后删除。访问时清理过期临时数据，后台每 30 秒补扫；日志和消息去重记录保留一天。账号与群绑定长期保留。

SQLite 当前 schema 为 5，启动时自动迁移。升级前备份数据库，并同时保存 `data/` 中的纹理与签名密钥；真实配置、数据和密钥不得提交 Git。

```text
uv run python -m nomi_auth.cli backup backups/nomi.sqlite3
uv run python -m nomi_auth.cli disable 注册时的账号名
uv run python -m nomi_auth.cli enable 注册时的账号名
```

停用会撤销令牌；已经在线的玩家需由游戏服另行踢出。临时数据自动清理，`cli cleanup` 可手动触发。

## 部署

`deploy/` 提供可选的 systemd 和 Nginx 通用模板，按自己的环境修改路径、域名和证书。真实配置、数据库与私钥仅保存在部署环境中。

检查代码：`uv run pytest -q`、`uv run ruff check src tests`。
