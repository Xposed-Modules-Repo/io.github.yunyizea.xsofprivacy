# 0.3.2-preview 验证记录

日期：2026-11-06。基于合并提交 `2ea1c44e` 修复，versionCode 7。

## 修复

- SystemHelper 3.0.1 保留有明确旧版证据的单发送实现，自适应识别与精确配置再次一致。
- 双发送实现要求唯一的加密方法、唯一的备用方法和共同调用方；缺失、未关联或歧义时跳过发送组。
- DEX 索引保留双发送调用方，即使该类不含原有字符串锚点。
- 主机检查器拒绝错误包名、空功能组列表和空目标组；输出改为 `MATCHED`，不再暗示主机端安装了 Hook。

## 已通过

- 所有 Java 源码、资源与 DEX 编译；7 项日志单元测试。
- 存档手机管家 12.8.7 的 28 个目标与既有缺失/歧义/重命名回归。
- 存档 GuardProvider 3.1.4 和 SystemHelper 3.0.1 的 11 个目标与返回策略回归。
- 补充真实 SystemHelper 4.0.0：10 组 / 11 个目标全部识别；双发送方法与共同调用方、重命名、缺失与歧义回归通过。
- 新增模拟索引测试：双发送、重命名、成功日志变化、未识别备用方法、缺失共同调用方、发送目标歧义、未知单发送实现。
- 检查器 6 个场景：两个正确 APK 成功；错误包名退出 2；错误 APK、空功能组、空目标退出 1。其中两个空结果场景使用临时替代 Resolver，验证检查器的拒绝行为。
- APK 版本、入口、minSdk 28、targetSdk 35、无新增权限；没有打包 Xposed 框架、JUnit 或测试类。
- v3 签名验证和资源 4 字节对齐检查。

构建使用本机 JDK 17、Android Platform 36.1 与 Build Tools 36.0.0 的直接工具链。
项目配置的 Platform 35/Build Tools 34.0.0 仍未安装，本次未完成标准 Gradle/Android Lint 检查。

## 产物与签名

文件：`app/build/outputs/apk/preview/xsof-privacy-0.3.2-preview.apk`。

APK SHA-256：`396e8060a5c26a701b2268a7df2341dadd7201bb20492730524e2f72aa7e0f26`。

证书 SHA-256：`22185a310f3a78dee876e3782996e16160f6d43484df668cabdf8d6f63da21f9`。
使用原预览签名，密钥与口令仍在仓库外，可覆盖使用同一证书的旧版。

## 待设备验证

使用者后来提供了小米 15 ROM 提取的真实 SystemHelper 4.0.0 APK，SHA-256 为
`0812ac78c41f29c835b78df5eab41ebda9491ffce290503c19c8b18a22c2482c`，
版本为 `4.0.0-20260610` / versionCode 34。主机端识别与真实 DEX 核对已通过，
运行时代码无需调整；现有已签名 0.3.2-preview APK 保持不变，无需为本次静态验证重新安装。
该文件走自适应路径，出现 `ADAPTIVE_UNVERIFIED` 是预期行为。

没有进行设备安装或动态网络验证。建议覆盖安装后重启，保留原作用域并开启详细日志；
对 4.0.0 重点检查 `helper.encrypted_post` 是否安装两个目标、是否出现 `SKIPPED`，
以及正常使用后是否出现该组的 `HIT`/`BLOCKED`。安装日志仅证明 Hook 注册，实际效果仍需结合设备行为。

包含真实 4.0.0 的完整主机回归命令：

```bash
python tools/run_resolver_tests.py targetApps/securitycenter-12.8.7-houji-os3.apk targetApps/guardprovider-3.1.4-houji-os3.apk targetApps/systemhelper-3.0.1-houji-os3.apk targetApps/systemhelper-4.0.0-dada-os3.apk
```
