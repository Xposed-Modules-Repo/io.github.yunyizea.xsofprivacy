# 0.3.0 验证范围

日期：2026-11-05。包名 io.github.yunyizea.xsofprivacy，versionCode 5，versionName 0.3.0-preview。

新增两个可选作用域：GuardProvider 的 AI 通话检测入口（1 个目标）以及 SystemHelper
中的许可判断、加密提交、应用统计线程和 7 类专用 Receiver（10 个目标）。原 XSOF
仍为 14 组、28 个目标。三个作用域合计 25 组、39 个目标，按进程分别安装。

已完成：

- 原 XSOF 全部 28 个目标的识别与缺失/歧义回归。
- 两个新增 APK 的 11 个目标、精确配置与特征配置一致性、返回值策略核对。
- 错误包/错误 APK、开关证据缺失、提交方法歧义、服务行为证据缺失的跳过测试。
- Java 17 编译、D8 8.7.18 DEX 生成、apksig 8.7.3 v3 签名验证。
- resources.arsc 不压缩，签名后偏移 788，满足 4 字节对齐。
- APK 包名/版本/入口一致，无额外权限、旧模块包名、测试类或框架实现。
- 作用域数组包括 com.miui.securitycenter、com.miui.guardprovider、com.mobiletools.systemhelper。

使用者提供 LSPosed 2.2.1 (7912)，HyperOS 3.0.307.0.WNCCNXM.C11。
原 XSOF 有使用者实机生效反馈；本次 0.3.0 新增功能未经过真机注入、停止效果、
采集变化、网络请求、耗电或长期稳定性验证。不能将编译和识别测试当作效果证明。

安装包沿用之前实验签名，使用 AAPT2+D8+apksig 直接构建；Gradle 未完整执行。
输入 APK 的信息、证据和行为边界见 docs/extended-analysis.md。

APK SHA-256：
`651b63fd37a8e38bc014e1bfb42f26693e077d9d3b771b0840fe98b4f8263221`
