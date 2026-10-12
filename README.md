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

统一申请登录码：已有账号直接登录，未注册成员在群内提交 `注册 <id>`。申请有效期默认 5 分钟，会话只能领取一次。支持本人改名和 HMCL 原生皮肤上传；改名默认冷却 7 天，UUID 不变。

领取或取消后立即删除申请，失败结果经私密查询后删除。访问时清理过期临时数据，后台每 30 秒补扫；日志和消息去重记录保留一天。账号与群绑定长期保留。

SQLite 当前 schema 为 4，启动时自动迁移。升级前备份数据库，并同时保存 `data/` 中的纹理与签名密钥；真实配置、数据和密钥不得提交 Git。

```text
uv run python -m nomi_auth.cli backup backups/nomi.sqlite3
uv run python -m nomi_auth.cli disable 注册时的账号名
uv run python -m nomi_auth.cli enable 注册时的账号名
```

停用会撤销令牌；已经在线的玩家需由游戏服另行踢出。临时数据自动清理，`cli cleanup` 可手动触发。

## lobby 部署

源码、`.venv`、`.env`、`data/` 均在 `/home/naipu/minecraft/nomi-auth`，归 `www-data:www-data`；`.env` 为 0600，data 目录为 0700。`nomi-auth.service` 管理开机自启及失败重启，监听 `127.0.0.1:8000`。

公网为 `https://auth.missdrop.cn`。EdgeOne HTTPS 回源 `https.missdrop.cn:20080`，SNI 为 `https.missdrop.cn`，HOST 为 `auth.missdrop.cn`。Nginx 禁止公网访问 `/internal/`，机器人从回环地址调用。配置模板见 `deploy/`，无需 Docker。

检查代码：`uv run pytest -q`、`uv run ruff check src tests`。公网 HTTPS 与 authlib-injector 通信已验证，完整游戏进服仍需联调。
