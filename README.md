# Nomi Auth

这是一个群验证码账号服务，也提供 Minecraft 使用的 Yggdrasil 接口。玩家通过 [Nomi Launcher](https://github.com/NomiTeam/nomi-launcher) 申请验证码，再由 [机器人插件](https://github.com/NomiTeam/nomi-auth-plugin) 确认群成员身份，不使用密码。

## 环境

- Python 3.12 或 3.13
- uv
- SQLite，或独立的 MySQL/MariaDB 数据库

## 运行

将 `.env.example` 复制为 `.env`，填写机器人应用 ID、群 OpenID 和双方一致的服务凭证，然后执行：

```shell
uv sync
uv run uvicorn nomi_auth.app:create_app --factory --host 127.0.0.1 --port 8000 --workers 1
```

接口说明见 [API.md](API.md)。`/health` 检查应用与数据库连接；认证根路径为 `/api/yggdrasil/`。服务不提供 HTML 页面，也不开放在线文档或 OpenAPI JSON。公网入口应使用 HTTPS。

## 配置

配置统一放在应用目录的 `.env`，完整字段见 `.env.example`。

| 配置 | 说明 |
| --- | --- |
| `NOMI_PUBLIC_URL` | 对外地址，用于生成皮肤 URL |
| `NOMI_DATA_DIR` | 数据目录，保存签名密钥和皮肤；SQLite 文件也在这里 |
| `NOMI_DATABASE_BACKEND` | `sqlite`（默认）、`mysql` 或 `mariadb` |
| `NOMI_MYSQL_HOST/PORT/DATABASE/USER/PASSWORD` | MySQL/MariaDB 连接配置 |

使用 MySQL/MariaDB 时，先创建独立空库和专用用户，给予建表及读写权限。表使用 InnoDB 和 utf8mb4；可选 Unix socket，或通过 `NOMI_MYSQL_SSL_CA` 验证远程连接证书。

## 账号规则

启动器只需申请登录码。有账号的成员直接登录，没有账号时按机器人提示发送 `注册 ID`，例如 `注册 Alice`。申请默认有效 5 分钟，先完成验证的人认领申请。

ID 为 3–16 位字母、数字或下划线。改名默认冷却 7 天，UUID 不变。皮肤支持默认模型和 slim 模型。

游戏令牌默认 24 小时，管理令牌 1 小时，刷新令牌 30 天。刷新令牌每次使用后轮换。登录领取与续期可使用同一请求 ID 在两分钟内重试，返回原凭据，不延长有效期。

领取或取消后删除申请；过期临时数据自动清理，日志和消息去重记录保留一天。停用账号会撤销令牌，已在线玩家仍需由游戏服踢出。

## 数据维护

```shell
uv run python -m nomi_auth.cli backup backups/nomi.tar.gz
uv run python -m nomi_auth.cli restore backups/nomi.tar.gz restored-data
uv run python -m nomi_auth.cli disable Alice
uv run python -m nomi_auth.cli enable Alice
uv run python -m nomi_auth.cli cleanup
```

备份包含数据库、正在使用的皮肤和签名私钥，不能公开。恢复只写入新目录，不覆盖已有数据。

从 SQLite 切换到 MySQL/MariaDB：

1. 停止旧认证服务，创建最终完整备份，保留旧数据目录。
2. 在目标环境恢复到新目录，将 `NOMI_DATA_DIR` 指向它，配置 MySQL/MariaDB 空库。
3. 执行 `uv run python -m nomi_auth.cli migrate-database restored-data/nomi-auth.sqlite3`。
4. 验证已有账号和皮肤后切换访问入口，避免新旧服务同时写入。

迁移只读源文件，在一个事务中导入并逐字段核对，非空目标会拒绝导入。账号、UUID、群绑定和令牌都会保留。MySQL 的完整备份同样包含 SQLite 快照，因此也能恢复回 SQLite。当前数据库版本为 5，SQLite 旧版本会在启动时升级。

## 项目结构

```text
src/nomi_auth/
├── app.py                 - 创建应用，组合各个管理对象
├── accounts.py            - 账号校验、创建和令牌签发
├── logins.py              - 统一登录与群成员注册
├── registrations.py       - 兼容旧版独立注册流程
├── sessions.py            - 会话领取、续期和撤销
├── profiles.py / skins.py - 改名、皮肤校验和文件存储
├── yggdrasil.py            - 游戏认证与材质签名
├── db.py / mysql.py        - 数据库事务和表结构升级
├── maintenance.py         - 备份、恢复和皮肤清理
├── transfer.py            - 数据库迁移与核对
└── runtime.py             - 限流和后台清理
```

登录、注册和游戏认证共用账号规则，避免各接口各自修改身份。写事务同时保护验证码认领、令牌轮换和皮肤文件发布；MySQL 使用连接级写锁，保留 SQLite 原有的操作顺序。

`deploy/` 提供 systemd 和 Nginx 示例。按实际环境修改路径和证书，systemd 从工作目录读取 `.env`。建议单进程运行；多实例的分布式限流和文件共享不在当前实现范围内。

## 开发检查

```shell
uv sync
uv run ruff check src tests
uv run ruff format --check src tests
uv run pyrefly check
uv run pytest -q
```

默认测试 SQLite。配置 `NOMI_TEST_MYSQL_DATABASE/USER/PASSWORD` 后，同一套测试也会检查真实 MySQL/MariaDB，可选 `NOMI_TEST_MYSQL_HOST/PORT`。测试会清空业务表，库名必须以 `nomi_auth_test_` 开头，不要使用生产库。
