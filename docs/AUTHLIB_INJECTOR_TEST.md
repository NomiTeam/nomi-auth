# authlib-injector 实际通信验证

测试日期：2026-10-12。

使用启动器内置的 authlib-injector 1.2.8，以 Java Agent 形式加载 Minecraft 1.20.1 的官方 Mojang authlib 4.0.43。测试服务使用当前 Nomi Auth 代码和独立 SQLite 数据库，地址为 http://127.0.0.1:18001/api/yggdrasil/，没有修改正常服务的账户或会话。

## 测试结果

以下检查分别在 Java 17 的 client 模式、Java 21 的 server 模式执行，均通过：

- GameProfileRepository 按名称查询角色，返回相同 UUID。
- MinecraftSessionService.joinServer 使用 Nomi 游戏令牌提交进服会话。
- hasJoinedServer 查询同一会话，返回相同角色 UUID。
- 错误 serverId 不返回已验证玩家。
- fillProfileProperties 取得带签名的 textures 属性。
- getTextures(profile, true) 由真正的 authlib 验证自建服务纹理签名，通过。
- 纹理模型返回 slim。
- 纹理 URL 可下载有效 PNG。
- 无效游戏令牌被拒绝，抛出 authlib AuthenticationException。

Agent 日志确认 HttpAuthenticationService、YggdrasilEnvironment、YggdrasilServicesKeyInfo、Property 和 TextureUrlChecker 被转换；请求实际进入 Nomi 的角色查询、join、hasJoined、profile 和纹理接口。

另外使用同一 Agent 对当前运行的 http://127.0.0.1:8000/api/yggdrasil/ 初始化，成功取得并解析认证元数据，Java 21 正常启动。

## 验证范围

此次验证使用真实 Mojang authlib 和 authlib-injector，不是仅用 HTTP 客户端模拟协议。测试通过表明上述版本和接口能够互通。尚未启动完整 Minecraft 客户端和真实游戏服务器；其他 Minecraft/authlib 版本、公网 HTTPS、自动连接 play.missdrop.cn 及服务器插件的行为需在对应游戏环境继续验证。
