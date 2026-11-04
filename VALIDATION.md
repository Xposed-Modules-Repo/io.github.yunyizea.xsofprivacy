# 0.2.0 验证范围

本次从整包版本锁定改为“精确 APK 快速路径 + 未知 APK 按功能特征识别”。
所有既有逻辑的更新应以 README 和本文件为准。

主机端测试结果见 tests/RESULTS.txt；覆盖当前 APK、重命名元数据夹具、
歧义候选、监听配对缺失、回调关系缺失和拒绝码证据变化。

已分析 APK：手机管家 12.8.7-260927.0.1，SHA-256：
`f4eda1b7b0f46521c93ddc75f7d833aec7bd48674c561e545f2b84a1edd6284c`。

未验证：Android 真机安装、LSPosed 注入、ART 内联条件、启动开销、日常稳定性、
第三方客户端行为、其他固件版本，以及采集和联网路径的完整覆盖。
编译和识别测试通过不等于全面隐私保护成功。

构建结果：Java 17 编译、D8 8.7.18 DEX 生成、apksig 8.7.3 v3 签名验证通过。
资源文件为 ZIP_STORED，签名后数据偏移 772，满足 4 字节对齐。
输出 APK versionCode=3 / versionName=0.2.0-preview，无权限声明；包含解析依赖、
Xposed 入口和依赖许可证，未打包 Xposed 框架实现、测试类、原 APK 或数据库。
Gradle 构建未完整执行；安装包使用直接 AAPT2 + D8 + apksig 工具链生成。

输出 APK SHA-256：
`63021c5f91a72b7f999633f1d9deccd4c57d645999bc913920fbfcd707aa4259`
