# Nomi Auth API

本文随源码维护。服务不开放 `/docs`、`/redoc` 或 `/openapi.json`，也不提供 HTML 页面。
请求和响应默认使用 JSON，皮肤上传使用 multipart/form-data。以下路径相对于认证服务地址。

## 通用约定

- 账号名：3–16 位英文字母、数字或下划线，名称冲突忽略大小写；改名保持 UUID。
- 时间为 Unix 秒。令牌只在签发时返回，应安全保管；数据库保存令牌哈希。
- 私有接口通过 `Authorization: Bearer <token>` 鉴权。不同令牌不可混用。
- 普通错误：`{"code":"INVALID_TOKEN","message":"…","request_id":"…"}`；字段校验错误为 422，凭证错误为 401/403，不存在为 404，状态冲突为 409。
- 数据库不可用返回 503 `DATABASE_UNAVAILABLE`；限流返回 429 `RATE_LIMITED`。这两类响应不保证包含 `request_id`。
- 默认同一来源 IP 每分钟普通请求 300 次、敏感 POST 请求 20 次。部署反代时应正确设置可信代理；不要信任任意客户端传入的转发头。
- 游戏令牌默认 24 小时、管理令牌 1 小时、刷新令牌 30 天；实际以配置及响应的到期时间为准。

## 推荐登录流程

1. 启动器 `POST /api/v1/logins`，发送 `{}`，不提交账号或密码。
2. 响应状态 201，包含 `request_id`、`code`、`poll_token`、`expires_at`、`group_label`。将 `登录 验证码` 交给玩家在指定群发送，申请默认有效 5 分钟。
3. 机器人从可信群事件取得成员身份，调用 `/internal/v1/logins/verify`。已有账号返回 `VERIFIED`，没有账号返回 `AWAITING_NAME`。
4. 未注册成员发送 `注册 ID` 后，机器人调用 `/internal/v1/logins/register`。成功返回 `REGISTERED`，申请转为 `VERIFIED`。
5. 启动器用 poll_token 查询申请，在 `VERIFIED` 后领取会话。关闭窗口应取消申请。

同一验证码由首个成功验证的成员领取，不使用第二验证码；机器人必须只转发真实消息事件中的身份，不能接受用户自报的成员 ID。

| 方法 | 路径 | 凭证与输入 | 成功结果 |
| --- | --- | --- | --- |
| POST | `/api/v1/logins` | 无；JSON `{}` | 201，登录申请 |
| GET | `/api/v1/logins/{request_id}` | poll_token | `status`、`expires_at`、`error` |
| DELETE | `/api/v1/logins/{request_id}` | poll_token | `{"status":"CANCELLED"}` |
| POST | `/api/v1/logins/{request_id}/session` | poll_token；可选 `X-Request-ID` | 会话，见下文 |

状态包含 `PENDING`、`AWAITING_NAME`、`VERIFIED`、`FAILED`；过期申请可能返回 `EXPIRED`，清理后返回 404。失败结果经私密查询后删除，领取与取消后立即删除申请。

领取会话示例（占位值不可使用）：

```json
{
  "login_name": "Alice",
  "management_token": "<management-token>",
  "refresh_token": "<refresh-token>",
  "refresh_expires_at": 1800000000,
  "game_expires_at": 1797500000,
  "game": {
    "accessToken": "<game-token>",
    "clientToken": "<client-token>",
    "selectedProfile": {"id": "<uuid-without-hyphens>", "name": "Alice"},
    "availableProfiles": [{"id": "<uuid-without-hyphens>", "name": "Alice"}]
  }
}
```

`login_name` 为注册时的登录标识，当前游戏名以 `selectedProfile.name` 为准。
登录领取与启动器续期可附带 64 位小写十六进制 `X-Request-ID`；网络重试应复用同一值和原凭证。两分钟内返回同一组凭据，不延长有效期；首次成功收到后不要重复使用。未提供此头的领取是一次性的。

## 机器人内部接口

下列接口均使用配置的机器人服务凭证，而非玩家令牌。机器人应用 ID 和群 OpenID 必须匹配服务配置。

验证码验证输入：

```json
{
  "code": "AAAA-BBBB-CCCC",
  "bot_app_id": "<app-id>",
  "group_openid": "<group-id>",
  "member_openid": "<member-id>",
  "event_id": "<message-event-id>"
}
```

注册与改名输入使用同样的四个身份/事件字段，将 `code` 替换为 `name`。
应用、群、成员 ID 长度上限 128，事件 ID 上限 256。相同操作的同一事件重复提交返回缓存结果；事件 ID 相同但内容不同会冲突。

| 方法 | 路径 | 输入 | 结果 |
| --- | --- | --- | --- |
| POST | `/internal/v1/logins/verify` | 验证码和身份 | `AWAITING_NAME` 或 `VERIFIED`；后者包含 `name`、`uuid` |
| POST | `/internal/v1/logins/register` | 身份和 `name` | `REGISTERED`、`name`、`uuid`；业务失败返回 `FAILED`、`code` |
| POST | `/internal/v1/profiles/rename` | 身份和 `name` | `RENAMED`、`name`、`uuid`；业务失败返回 `FAILED`、`code` |
| POST | `/internal/v1/registrations/redeem` | 验证码和身份 | 兼容独立注册申请；`COMPLETED` 或 `FAILED` |

名称冲突、无效名称等注册失败会结束本次申请。常见错误包括 `NAME_TAKEN`、`INVALID_NAME`、`NO_PENDING_REGISTRATION`、`REQUEST_IN_PROGRESS`、`CODE_USED`、`WRONG_GROUP`、`ACCOUNT_UNAVAILABLE`；HTTP 200 的业务结果也应检查 `status`。

## 会话、角色与皮肤

| 方法 | 路径 | 凭证与输入 | 结果 |
| --- | --- | --- | --- |
| POST | `/api/v1/sessions/refresh` | refresh_token；可选 `X-Request-ID` | 新游戏及刷新令牌，格式同会话但无管理令牌 |
| DELETE | `/api/v1/sessions/refresh` | refresh_token | 204；撤销同一设备的游戏、刷新令牌 |
| GET | `/api/v1/game/profile` | game accessToken | `id`、当前 `name` |
| PATCH | `/api/v1/game/profiles/{profile_id}/name` | game accessToken；`{"name":"NewName"}` | 更新后的 `login_name`、`game`，UUID 不变 |
| GET | `/api/v1/me` | management_token | `login_name` 和 `profile`（UUID、账号 ID、名称、皮肤等） |
| PATCH | `/api/v1/me/profile/name` | management_token；`{"name":"NewName"}` | `uuid`、`name` |
| PUT | `/api/v1/me/profile/skin` | management_token；multipart `image`、`model` | `hash`、`url` |
| DELETE | `/api/v1/me/profile/skin` | management_token | 204，恢复默认皮肤 |
| DELETE | `/api/v1/sessions/current` | management_token | 204，仅撤销该管理令牌 |
| GET | `/textures/{texture_hash}` | 无 | PNG；不存在为 404 |

刷新令牌单次轮换，可在游戏令牌过期后使用；到期或被撤销后必须重新群验证。修改名称默认冷却 7 天；名称冲突不会改变原角色。
皮肤仅接受不超过 1 MiB 的 PNG（64×64 或 64×32），服务会重编码；`model` 为 `default` 或 `slim`。URL 使用配置的公网地址，材质按内容哈希长期缓存。

## Yggdrasil / authlib-injector

认证根路径为 `/api/yggdrasil/`。下表路径均加此前缀；用于游戏会话的凭证是 `game.accessToken`，不能使用管理或刷新令牌。

| 方法 | 相对路径 | 输入 | 结果 |
| --- | --- | --- | --- |
| GET | `/`（也支持不带末尾斜杠） | 无 | 元数据、皮肤域名和材质签名公钥 |
| POST | `/authserver/authenticate`、`/authserver/signout` | 任意 | 403；密码认证已禁用 |
| POST | `/authserver/refresh` | `accessToken`；可选 `clientToken`、`selectedProfile` 对象、`requestUser` | 单次轮换游戏令牌，返回新 `accessToken`、`clientToken`、`selectedProfile` |
| POST | `/authserver/validate` | `accessToken`；可选 `clientToken` | 204，失效为 403 |
| POST | `/authserver/invalidate` | `accessToken`；可选 `clientToken` | 204 |
| POST | `/sessionserver/session/minecraft/join` | `accessToken`、`selectedProfile` UUID 字符串、`serverId` | 204；加入凭据有效 30 秒 |
| GET | `/sessionserver/session/minecraft/hasJoined` | 查询参数 `username`、`serverId` | 含签名材质的角色；未验证为 204 |
| GET | `/sessionserver/session/minecraft/profile/{profile_id}` | 可选查询参数 `unsigned=false` | 角色和材质；不存在为 204 |
| POST | `/api/profiles/minecraft` | 名称字符串数组，最多 100 个 | `[{"id":"…","name":"…"}]`，忽略不存在名称 |
| PUT | `/api/user/profile/{profile_id}/skin` | Bearer game accessToken；multipart `file`、`model` | 204，仅限本人角色 |

原生皮肤接口的 `model` 可为 `slim`、`default`，空值代表默认模型。Yggdrasil 错误使用 `error`、`errorMessage`，参数错误通常为 400。

## 兼容独立注册接口

新启动器推荐使用统一登录流程。以下接口为旧调用保留：

| 方法 | 路径 | 凭证与输入 | 结果 |
| --- | --- | --- | --- |
| GET | `/api/v1/names/availability` | 查询参数 `name` | `{"available":true}`；不预占名称 |
| POST | `/api/v1/registrations` | `{"name":"Alice"}` | 201，结构同登录申请 |
| GET | `/api/v1/registrations/{request_id}` | poll_token | `status`、`expires_at`、`error`，验证成功为 `COMPLETED` |
| DELETE | `/api/v1/registrations/{request_id}` | poll_token | `CANCELLED` |
| POST | `/api/v1/registrations/{request_id}/session` | poll_token | 一次性领取会话 |

## 健康检查

`GET /health` 无需鉴权，执行数据库 `SELECT 1`，成功返回 `200 {"status":"ok"}`。
数据库连接失败返回 503。它仅检查应用与数据库连接，不检查机器人在线、QQ API、游戏服或反代证书，也不代表数据库写入和皮肤目录可用。入口仍受普通请求限流，建议每 30–60 秒检查一次。
