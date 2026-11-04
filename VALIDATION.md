# 0.2.1 验证范围

本次将模块 applicationId、namespace 和 Java 包名改为
`io.github.yunyizea.xsofprivacy`，并同步修改 Xposed 入口、测试入口和源码路径。
versionCode=4，versionName=0.2.1-preview。识别与拦截逻辑未变。

已完成：

- Java 17 编译及 D8 8.7.18 DEX 生成。
- 当前目标 APK 的全部 28 个方法识别、元数据重命名、歧义候选、
  监听配对缺失、回调缺失和拒绝码证据变化测试，见 tests/RESULTS.txt。
- apksig 8.7.3 签名验证通过。
- APK 包名、版本、Xposed 入口与 DEX 中入口类一致。
- 未打入旧模块包名的类、测试类或 Xposed 框架实现。
- resources.arsc 为 ZIP_STORED，签名后偏移 788，满足 4 字节对齐。
- 安装包无额外 Android 权限声明，ZIP 完整性检查通过。

原 0.2.0 已有使用者在小米 14 国行系统
3.0.307.0.WNCCNXM.C11、手机管家 12.8.7-260927.0.1 上实机验证有效的反馈。
本次 0.2.1 新包尚未实机安装复验，也未验证外部模块仓库的提交审核结果。
Gradle 构建未完整执行；安装包使用 AAPT2 + D8 + apksig 直接工具链构建。

包名变化后不能覆盖安装旧包。应禁用并卸载旧模块，安装新包后重新设置
手机管家作用域并重启。功能边界与适配限制见 README.md。

输出 APK SHA-256：
`995c05e56091f74e037bc0043c93b7da8c43d7d369895219b85702ec65628ea4`
