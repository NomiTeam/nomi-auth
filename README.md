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

- 启动器统一调用 `POST /api/v1/logins`，请求体为空或 `{}`，在群内发送 `登录 <码>`。
- 插件调用 `/internal/v1/logins/verify`，已有账号返回 VERIFIED 与当前游戏名；没有账号进入 AWAITING_NAME，认领给发送码的成员。
- 该成员通过 `注册 <id>` 调用 `/internal/v1/logins/register`；原子创建账号、角色与群绑定，进入 VERIFIED。冲突或格式错误记为 FAILED 并结束申请。
- 使用私密 poll_token 查询和取消申请，再向 `/api/v1/logins/{id}/session` 单次领取会话。申请默认 5 分钟有效；每个成员同一时间只允许一个待注册申请。
- 群内 `改名 <新id>` 调用 `/internal/v1/profiles/rename`，按事件身份修改本人名称，默认冷却 7 天，UUID 永不改变。
- 注册、验证、改名结果包含当前 ID（游戏名）与角色 UUID；只有启动器持有的私密凭证可领取令牌，机器人回复不包含任何令牌。
- 旧 `/api/v1/registrations` 接口保留兼容，当前启动器和机器人不使用。传统 authenticate 和 signout 不接受密码；游戏令牌支持 refresh、validate、invalidate 和进服会话。

## 数据与维护

SQLite schema 版本 2 移除旧密码字段并撤销旧会话；版本 3 添加登录申请认领成员与错误字段，版本 4 添加去重记录时间及清理索引。迁移保留账号、群身份与 UUID。升级前先使用 SQLite backup API 做备份。签名密钥与纹理位于 `NOMI_DATA_DIR`，服务重启复用，不得公开或提交这些文件。

```text
uv run pytest -q
uv run ruff check src tests
uv run python -m nomi_auth.cli backup backups/nomi.sqlite3
uv run python -m nomi_auth.cli cleanup
uv run python -m nomi_auth.cli disable Alice
uv run python -m nomi_auth.cli enable Alice
```

备份数据库时同时备份纹理与签名私钥。服务内部自动清理：领取或取消后删除申请，失败结果经私密查询后删除，访问时删除过期临时数据；后台每 30 秒补扫无人访问的记录。操作日志和消息去重记录保留一天。cleanup 仅用于手动维护。停用账号保留群绑定并撤销令牌，已在线玩家由游戏服管理员另行踢出。

`deploy/` 提供 systemd、环境配置和 Nginx 示例，无需 Docker。当前服务器统一放在 `/home/naipu/minecraft/nomi-auth`：源码、`.venv/`、`.env`、`data/` 都在应用目录下，归 `www-data:www-data` 所有。`.env` 权限 0600、data 目录 0700。服务 `nomi-auth.service` 开机自启并在失败时重启，后端仅监听 127.0.0.1:8000。

公网域名为 `auth.missdrop.cn`，EdgeOne 以 HTTPS 回源 `https.missdrop.cn:20080`，回源 SNI 为 https.missdrop.cn，Host 为 auth.missdrop.cn。Nginx 复用 https.missdrop.cn 证书，并禁止公网访问 /internal/。EdgeOne/DNS 已配置完成。公网 HTTPS 健康检查、认证元数据、签名角色查询、登录申请与取消均已验证通过；真实 authlib-injector 1.2.8 经公网地址初始化正常。

机器人位于 `/home/naipu/minecraft/nomi-bot`，归 mcadmin 所有，由 bot.service 管理，通过回环地址调用后端内部接口。使用 uv 安装到不同用户的虚拟环境时设置 `--link-mode copy`，避免硬链接的所有权相互影响。


## HMCL 原生皮肤上传

角色资料提供 `uploadableTextures=skin`。`PUT /api/yggdrasil/api/user/profile/{uuid}/skin` 使用游戏 Bearer 令牌、multipart `file` 与 `model`；空模型表示 default，slim 表示细手臂，成功返回 204。只允许修改令牌所属角色。

启动器账户按钮使用 `PATCH /api/v1/game/profiles/{uuid}/name`，以游戏 Bearer 令牌限定本人角色；返回更新后的游戏会话资料，UUID 与令牌保持不变。与群内改名共用名称唯一性及冷却规则。
