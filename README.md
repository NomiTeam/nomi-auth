# Nomi Auth

支持 SQLite、MySQL/MariaDB 的 FastAPI 单群账号与 Yggdrasil 服务，供 [Nomi 启动器](https://github.com/NomiTeam/nomi-launcher)和 [QQ 机器人插件](https://github.com/NomiTeam/nomi-auth-plugin)使用，不存储用户密码。

## 本地运行

需要 Python 3.12/3.13 和 uv。复制 `.env.example` 为 `.env`，填写机器人应用 ID、群 OpenID 和与插件一致的服务凭证，再执行：

```text
uv sync
uv run uvicorn nomi_auth.app:create_app --factory --host 127.0.0.1 --port 8000 --workers 1
```

接口文档见 [API.md](API.md)，健康检查 `/health`，认证根路径 `/api/yggdrasil/`。公网地址使用 HTTPS。服务不提供 HTML 文档页面或 OpenAPI JSON 入口。

## 账号与数据

统一申请登录码：已有账号直接登录，未注册成员在群内提交 `注册 <id>`。申请有效期默认 5 分钟，每次验证只签发一组会话。支持本人改名和 HMCL 原生皮肤上传；改名默认冷却 7 天，UUID 不变。

游戏令牌默认 24 小时，管理令牌 1 小时；启动器另持有 30 天刷新令牌，使用时单次轮换并重新计算 30 天有效期。登录领取和续期支持同一请求在两分钟内重试，返回原凭据且不延长有效期；重试记录只存哈希和随机值，过期自动清理。刷新接口只接受刷新令牌，停用账号会撤销所有令牌。旧账户需重新群验证一次领取刷新令牌。

领取或取消后立即删除申请，失败结果经私密查询后删除。访问时触发合并清理，最多每 30 秒执行一次，后台补扫；日志和消息去重记录保留一天。账号与群绑定长期保留。

数据库 schema 为 5；SQLite 旧版本启动时自动升级。升级前创建完整备份；真实配置、数据和密钥不得提交 Git。

```text
uv run python -m nomi_auth.cli backup backups/nomi.tar.gz
uv run python -m nomi_auth.cli disable 注册时的账号名
uv run python -m nomi_auth.cli enable 注册时的账号名
```

备份包含数据库、当前使用的皮肤和签名私钥，应妥善保管。恢复到新目录：`uv run python -m nomi_auth.cli restore backups/nomi.tar.gz restored-data`，停服后再切换数据目录。未引用的旧皮肤保留至少一天后自动清理。

停用会撤销令牌；已经在线的玩家需由游戏服另行踢出。临时数据自动清理，`cli cleanup` 可手动触发。

## 数据库选择与迁移

默认 `NOMI_DATABASE_BACKEND=sqlite`，现有配置不必修改。使用 MySQL 8.0+ / MariaDB 10.6+ 时，在 `.env` 中设为 `mysql` 或 `mariadb`，填写 `NOMI_MYSQL_HOST/PORT/DATABASE/USER/PASSWORD`（见 `.env.example`）。由管理员预建独立的空数据库与专用用户；表使用 InnoDB、utf8mb4，应用用户需要建表和读写权限。可配置 Unix socket，远程连接可通过 `NOMI_MYSQL_SSL_CA` 启用证书与主机名验证。

切换后端不会自动搬数据。SQLite 迁往 MySQL/MariaDB：

1. 停止旧认证服务，按上面的 `backup` 命令制作最终完整备份，保留旧目录以便回退。
2. 在目标环境 `restore` 到新数据目录，将 `NOMI_DATA_DIR` 指向它，并配置 MySQL/MariaDB 空库。
3. 执行 `uv run python -m nomi_auth.cli migrate-database 新数据目录/nomi-auth.sqlite3`。导入在一个事务内完成，逐表核对行数及所有字段；失败回滚，非空目标拒绝覆盖，源文件只读。
4. 检查 `/health`、已有账号登录和皮肤后切换访问入口，保持旧服务停用，避免双写。

账号、UUID、群绑定、令牌及重试记录全部保留；签名密钥和皮肤由完整备份恢复。机器人 API 不变。MySQL 的 `backup` 同样生成包含 SQLite 快照的完整备份，可直接恢复回 SQLite；备份期间写入会等待，日常读取不受影响。部署仍建议单个服务进程，共享数据目录；多实例的限流和文件存储不在本次数据库支持范围内。

## 部署

`deploy/` 提供可选的 systemd 和 Nginx 通用模板，按自己的环境修改路径、域名和证书。配置统一由根目录 `.env.example` 复制为应用目录下的 `.env`，systemd 从工作目录加载它。真实配置、数据库与私钥仅保存在部署环境中。

检查代码：`uv run pytest -q`、`uv run ruff check src tests`。默认跑 SQLite；设置 `NOMI_TEST_MYSQL_DATABASE`、`NOMI_TEST_MYSQL_USER`、`NOMI_TEST_MYSQL_PASSWORD` 后同一测试套件也跑真实 MySQL/MariaDB，可选 `NOMI_TEST_MYSQL_HOST/PORT`。测试库名必须以 `nomi_auth_test_` 开头，测试会清空其中业务数据，勿使用生产库。
