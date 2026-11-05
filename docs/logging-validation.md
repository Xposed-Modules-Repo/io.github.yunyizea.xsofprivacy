# 0.3.1 日志功能验证

日期：2026-11-05。包名 `io.github.yunyizea.xsofprivacy`，versionCode 6，versionName `0.3.1-preview`。

## 行为与安全边界

- 管理 Activity 提供详细日志开关，默认关闭，桌面与 LSPosed 模块设置均有入口。
- 设置使用私有 SharedPreferences；导出的 Provider 只接受读取布尔值，不接收日志或提供写入接口。Activity 不从 Intent 参数修改设置。
- 三个作用域的每次已安装 Hook 拦截都可输出 `BLOCKED`；关闭时保留安装、错误和首次 `HIT` 等基础日志。
- 日志仅包含调用元数据和拦截处理结果，不序列化调用参数，不记录数据库内容、Intent 内容、电话号码或应用列表。
- 每个进程最多每秒读取一次设置；读取失败暂停详细输出并重试，持续失败仅输出一次状态警告，恢复时记录状态。
- 详细日志在原方法已被跳过后生成，设置读取和日志输出异常不会撤销拦截。

## 本次验证

- 全部 Java 源码与 Android 资源编译通过，D8 生成 DEX 通过。
- 日志单元测试 7 项通过：默认关闭、开关双向刷新、每次命中、日志字段与处理结果、读取失败恢复、输出失败隔离、并发读取限制。
- 原 XSOF 28 个目标的真实 APK 特征匹配与重命名、缺失、歧义回归通过。
- 恢复仓库测试脚本引用但缺失的 `tests/ExtendedResolverTest.java`；新增作用域 11 个目标与返回策略、错误 APK/包、缺失证据与歧义回归通过。
- APK 包名、版本、minSdk 28、targetSdk 35、可启动 Activity 已检查；无新增权限。
- APK v3 签名验证通过；`resources.arsc` 不压缩且 4 字节对齐。

构建使用本机 JDK 17、Android SDK Platform 36.1（targetSdk 仍为 35）、Build Tools 36.0.0 的 AAPT2/Javac/D8/apksigner 直接工具链。最初的 debug APK 使用本机 Android debug keystore；按使用者要求，已使用项目目录之外的预览签名重新签署，最终安装包为 `app/build/outputs/apk/preview/xsof-privacy-0.3.1-preview.apk`。私钥与口令没有写入仓库。

最终 APK SHA-256：`45162669730fd9758b31df630e95a656b52a90fec6b4f6a884ed87118f8f198f`。

签名证书 SHA-256：`22185a310f3a78dee876e3782996e16160f6d43484df668cabdf8d6f63da21f9`。与签名目录说明中的证书一致，重新签名后的 v3 签名和资源 4 字节对齐均已验证。旧模块若使用同一签名，可覆盖更新；若使用本机 debug 签名或其他签名，则仍需卸载后重装。

标准 Gradle 构建及 Android Lint 未完成：本机缺少项目配置的 Platform 35/Build Tools 34.0.0，SDK 仓库未能获取这些包。JDK 的回环连接错误可通过仅对构建进程设置 `-Djdk.net.unixdomain.tmpdir` 到本地构建目录绕过，没有修改全局 Java 配置。

## 待实机验证

本次没有连接 Android 设备或可用 AVD，未验证 Activity 渲染、设置持久化、跨应用 Provider 的实际可访问性、LSPosed 设置入口和逐次日志输出。建议：

1. 安装新版并重启，使所有目标进程加载新代码。
2. 从桌面打开日志设置，开启开关；触发正常操作，检查 `BLOCKED` 的组、方法和结果。
3. 关闭开关，等待至少 1 秒并再次操作，确认没有新的 `BLOCKED`，拦截继续。
4. 分别检查三个作用域；若有 `DETAIL_SETTINGS_UNAVAILABLE`，记录异常类型与系统限制，不能认定详细日志已启用。
5. 重新打开设置及重启手机检查开关持久化，同时验证日常功能正常。
