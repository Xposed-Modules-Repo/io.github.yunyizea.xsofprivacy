# XSOF Privacy

用于小米 HyperOS 的 LSPosed 隐私控制模块。按作用域选择手机管家 XSOF、GuardProvider 的 AI 通话检测，以及 SystemHelper 的部分运营商遥测路径。

当前版本：**0.3.1-preview**，模块包名为 `io.github.yunyizea.xsofprivacy`。原有 XSOF 功能已有实机生效反馈；新增的两个作用域只完成静态识别和构建检查，尚需真机验证。

## 功能

- **行为监听拦截**：拦截已识别的截图、电话状态、SIM 状态、飞行模式等监听注册，以及呼叫转移状态查询和相关网络状态监听。
- **本地记录写入拦截**：针对截图、应用安装、通话、屏幕共享等行为记录的插入和更新路径进行拦截。
- **Provider 写入拦截**：阻止通过已识别的 `FraudDetectionProvider` 内部写入入口提交数据。
- **对外接口拦截**：拒绝已识别的当前行为、历史行为、行为持续时长和风险评分查询。
- **后续版本适配**：通过 DEX 特征和调用关系寻找目标，不以固定版本号限制加载。
- **按功能记录状态**：分别报告匹配、安装、首次命中、跳过和失败，便于检查实际覆盖情况。

模块作用于手机管家进程，不修改原始系统 APK，也不自动删除已有行为记录。

## 实机验证

| 项目 | 已反馈的测试环境 |
|---|---|
| 设备 | Xiaomi 14 / 小米 14 |
| 系统版本 | `3.0.307.0.WNCCNXM.C11`，国行 HyperOS |
| Android | 16 |
| 手机管家 | `12.8.7-260927.0.1` |
| 手机管家 versionCode | `40001287` |
| 测试反馈 | 模块实机验证有效 |
| LSPosed | 使用者提供版本 `2.2.1 (7912)`，分支名称未提供 |

上述为已反馈的设备环境和生效结果，不代表所有功能、第三方应用兼容性和长期稳定性均已逐项验证。其他机型、系统区域和手机管家版本仍需自行检查日志与实际行为。

## 环境要求

- 已取得 Root 权限。
- 安装了兼容当前 Android 版本的 LSPosed，并支持传统 Xposed API 82。
- 系统安装了小米手机管家：`com.miui.securitycenter`。

本模块采用传统 Xposed API；仅支持现代 API 的框架环境不能直接视为兼容。

## 安装

1. 下载发布的模块 APK；从源码构建时，安装 `app/build/outputs/apk/debug/app-debug.apk`。
2. 在 LSPosed 管理器中启用 **XSOF Privacy Preview**。
3. 按下表选择需要的作用域，无需选择系统框架。只选手机管家时不会启用新增两项功能。
4. 重启手机，使原有进程退出并重新加载模块。
5. 查看 LSPosed 日志，搜索 `XsofPrivacy`，确认相关进程和功能组的状态。

模块提供独立的日志设置 Activity，可从桌面或 LSPosed 的模块设置入口打开，不需要额外授予模块应用权限。

| 可选作用域 | 包名 | 启用影响 |
|---|---|---|
| 手机管家 | `com.miui.securitycenter` | 原有 XSOF 监听、写入和查询拦截 |
| 系统安全组件 / GuardProvider | `com.miui.guardprovider` | 停用已识别的 AI 通话音视频检测服务及该服务统计 |
| SystemHelper | `com.mobiletools.systemhelper` | 阻止已识别的遥测采集入口与加密提交，可能影响终端注册/运营商体验计划统计 |

建议分别启用新增作用域、重启并检查日志。该模块没有全局禁用网络、定位 SDK、媒体 API 或整个杀毒服务。


### 更新与停用

更新模块后重启手机。停用时，在 LSPosed 中禁用模块并重启即可恢复原程序行为。

0.2.1 将模块包名从 `local.xsofprivacy` 改为 `io.github.yunyizea.xsofprivacy`，Android 会把它视为新的应用。请先在 LSPosed 中禁用并卸载旧模块，再安装新版、重新启用并选择手机管家作用域，最后重启。不要同时启用新旧两个模块。

若更新提示签名不一致，可卸载旧的 **XSOF Privacy 模块**后重新安装，再启用并设置作用域；不需要卸载手机管家。

## 工作原理

模块在所选目标应用的 `Application.attach()` 完成后进行初始化，并在目标进程中安装 Hook。它采用两条识别路径。

### 已分析 APK：精确适配

当 base APK 与已分析文件的 SHA-256 完全一致、且没有 split APK 时，使用已经核对的方法列表，省去 DEX 特征扫描。

已分析 APK 的 SHA-256：

```text
f4eda1b7b0f46521c93ddc75f7d833aec7bd48674c561e545f2b84a1edd6284c
```

该哈希用于选择精确适配路径，**不再作为阻止其他版本加载的条件**。

### 其他 APK：特征识别

哈希不匹配时，扫描 base APK 与 split APK 中的标准 `classes*.dex`，结合以下证据识别目标：

- 类的父类和方法参数、返回类型。
- 数据库名、表名、字段及相关操作。
- 广播事件、接口标识及其他字符串特征。
- 初始化、写入、查询和回调之间的直接调用关系。

`Ra.k`、`e1` 等混淆名称变化后，只要所需特征和结构仍符合匹配条件，就可以继续识别。候选缺失或不唯一时，跳过对应功能组，不任意选择一个候选。

这是对后续版本的适配能力，不是对所有未来实现的兼容承诺。日志中的 `ADAPTIVE_UNVERIFIED` 表示使用了特征匹配路径，不表示匹配失败。

### 功能分组

手机管家策略包含 **14 个功能组、28 个 Hook 目标**：

| 功能组 | 目标数 | 拦截范围 |
|---|---:|---|
| `listeners` | 10 | 监听注册、状态查询及配套清理 |
| `storage.*` | 11 | 8 类记录的插入与部分更新 |
| `provider.ingress` | 3 | Provider 内部写入入口 |
| `api.*` | 4 | 当前行为、历史行为、持续时长和评分接口 |

8 类本地记录对应表为：

```text
airplane_mode
call_forwarding
fraud_phone
fraud_url
install_app
screen_share
screenshot
voip_record
```

每组完整解析后才安装该组 Hook，失败时尝试撤销该组已经安装的 Hook。监听注册与清理作为一个整体处理，避免只跳过清理而留下运行中的监听。

对外查询使用匹配实现中的拒绝回调 `(null, 1017)`，不返回伪造的“零风险”评分。依赖这些接口的应用可能出现权限或安全服务错误，需要检查常用应用的实际表现。

## 日志说明

日志前缀包含目标进程名，例如：

```text
[XsofPrivacy][com.miui.securitycenter:remote] INSTALLED storage.screenshot hooks=1
```

上例为格式示意，不是附带的实机日志。

| 标记 | 含义 |
|---|---|
| `PROFILE=EXACT_APK` | 使用已分析 APK 的精确方法列表 |
| `PROFILE=ADAPTIVE_UNVERIFIED` | 使用未知 APK 的特征匹配结果 |
| `INSTALLED` | 对应功能组已注册 Hook |
| `HIT` | 对应方法在该进程中首次实际进入拦截 |
| `SKIPPED` | 证据缺失或存在歧义，该功能组未启用 |
| `FAILED` | 该组安装失败，并尝试撤销已经安装的 Hook |
| `FAILED_ROLLBACK_INCOMPLETE` | 未能确认该组 Hook 全部撤销，应禁用模块并重启 |
| `CALLBACK_FAILED` | 拒绝回调发送失败，客户端可能超时 |
| `DISCOVERY_FAILED` | 扫描或准备失败，不能据此认为拦截生效 |
| `BLOCKED` | 开启详细日志后，每次已安装 Hook 跳过原方法的记录 |
| `DETAIL_SETTINGS_UNAVAILABLE` / `DETAIL_SETTINGS_RECOVERED` | 跨进程日志设置读取失败或恢复，失败期间暂停详细输出 |
| `SUMMARY` | 汇总安装、跳过或失败的组数、Hook 数和初始化耗时 |

**安装成功、Hook 注册成功和实际拦截生效是不同阶段。** 检查 `INSTALLED` 后，还应结合 `HIT` 和实际记录变化判断效果。

基础 `HIT` 日志仍只记录每个方法在每个进程中的首次命中。模块日志不输出电话号码、行为数据库内容或调用参数。

### 详细拦截日志开关（0.3.1）

打开 **XSOF Privacy · 日志设置**，启用“详细拦截日志”（默认关闭）。开启后，每次已安装 Hook 拦截都会向 LSPosed 输出一条 `BLOCKED`，涵盖三个作用域，而不只记录首次命中。

详细记录包含 UTC 时间、目标包与进程、应用版本、适配方式、PID/TID、Binder 调用 UID、功能组、完整 DEX 方法签名、该方法在当前进程的累计命中次数、跳过原方法后的返回策略、拒绝回调及停止服务请求的结果。例如：

```text
[XsofPrivacy][com.miui.securitycenter:remote] package=com.miui.securitycenter version=12.8.7-260927.0.1 profile=EXACT_APK pid=1234 BLOCKED time=2026-11-05T08:00:00Z tid=1235 callingUid=1000 group=storage.screenshot method=LRa/k;->e1(LQa/k;)V hit=2 original=skipped result=void callback=not_applicable serviceStop=not_applicable
```

上例仅为格式示意。`callingUid` 表示执行 Hook 时的 Binder 调用身份；普通进程内调用通常为自身 UID，不能单凭它认定是某个外部应用发起。`serviceStop=requested` 只表示已请求停止，不证明服务已经停止。回调会区分 `rejected:1017`、`missing` 和 `failed:异常类型`。

开关保存在模块的私有设置中。目标进程通过只读 Provider 读取布尔值，每个进程最多每秒读取一次；修改后无需重启，在下一次拦截时刷新，缓存最长 1 秒。设置读取失败时关闭详细输出并在后续轮询重试；拦截继续执行。未解锁、模块被强行停止或系统限制跨应用访问时，详细输出可能暂不可用。

关闭开关只停止逐次 `BLOCKED` 输出，安装、首次命中、错误等基础日志仍保留；已输出的日志不会被删除，开启前的事件不会补记。日志保留及导出由 LSPosed 管理，设置页仅管理开关。详细日志可能较多，排查完成后建议关闭。

## 如何确认生效

1. 启用模块并重启，检查手机管家相关进程的日志，包括 `remote` 进程。
2. 确认需要的功能组出现 `INSTALLED`，检查是否存在 `SKIPPED` 或 `FAILED`。
3. 对截图等事件进行少量正常操作，观察相应的 `HIT` 日志。
4. 需要核对本地写入时，重新获取最新的 `fraud_detection_data.db` 副本，比较对应表的记录数和最新时间。
5. 分别验证其他事件路径，并确认日常通话、应用安装、权限管理和常用应用工作正常。

已有记录不会被模块删除；数据库自动清理也可能造成数量下降，因此不应只看总数。服务仍出现在 `dumpsys` 中，也不能直接说明模块无效：模块保留服务生命周期，拦截的是内部方法。

## 构建

| 依赖 | 版本 |
|---|---|
| JDK | 17 |
| Android SDK Platform | 35 |
| Android Gradle Plugin | 8.7.3 |
| Gradle | 8.9 |
| Xposed API | 82，`compileOnly` |
| dexlib2 | 2.5.2 |

使用 Android Studio 打开项目目录并同步，随后构建 `app`；已安装 Gradle 8.9 的环境也可执行：

```bash
gradle :app:assembleDebug
```

产物位于 `app/build/outputs/apk/debug/`。当前源码未附带 Gradle Wrapper，不应直接使用 `./gradlew`。

Xposed API 由运行时框架提供，不打入模块 APK；DEX 解析所需依赖随模块打包。第三方许可证位于 `app/src/main/assets/third-party/`。

现有预览 APK 使用 AAPT2、D8 和 apksig 直接工具链构建；Gradle 构建尚未完整执行验证。`resources.arsc` 的不压缩存储、4 字节对齐及 APK 签名已检查。

直接工具链构建时，Xposed API 必须保持 `compileOnly` 语义，**不能打进模块 APK**。
若把 `de.robv.android.xposed` 的类编入 DEX，LSPosed 会拒绝加载并报
`Cannot load module: The Xposed API classes are compiled into the module's APK.`
。用 D8 构建时需把这些 class 从输入中排除，仅以 classpath 形式提供。

若要在主机端先确认某个新版本 APK 能否被识别，不必刷入设备：

```bash
python tools/check_extended_resolver.py /path/to/systemhelper.apk com.mobiletools.systemhelper
```

脚本用模块自己的解析器扫描目标 APK，打印每个功能组的目标与返回策略；
任一功能组被跳过时以非零码退出。需要先用 javac 把 `app/src/main/java`
编到 `../tools/build/cls`，dexlib2 与 guava 放在 `../tools/libs`。
APK 只被读取，不会执行。

## 测试

除上述实机生效反馈外，项目包含主机端识别回归测试：

日志开关、连续命中、失败恢复和并发读取的单元测试可运行 `gradle :app:testDebugUnitTest`。0.3.1 本地构建与验证限制见 [日志功能验证记录](docs/logging-validation.md)。

```bash
python tools/run_resolver_tests.py /path/to/securitycenter-12.8.7.apk
```

需要 Python 与包含 `jdk.compiler` 的 Java 17 环境。脚本在临时目录下载并校验固定依赖，不执行或修改目标 APK。

已覆盖的识别场景：

- 在已分析 APK 上强制走特征识别，结果与精确配置的 28 个目标一致。
- 在索引测试数据中模拟类名、方法名及回调名变化。
- 多个匹配候选时跳过相关功能组。
- 监听注册证据缺失时跳过整组配对逻辑。
- 回调关系或拒绝码证据变化时跳过受影响接口。

测试源码见 `tests/ResolverTest.java`，结果见 `tests/RESULTS.txt`。重命名场景是索引测试数据，不等于已经测试真实的后续固件。

## 源码结构

| 文件 | 职责 |
|---|---|
| `PrivacyHook.java` | 入口、识别路径选择、按组安装 Hook、回调和日志 |
| `SettingsActivity.java` | 详细拦截日志的开关界面 |
| `LoggingSettings.java` / `LoggingSettingsProvider.java` | 私有设置与只读跨进程开关读取 |
| `InterceptionLog.java` | 逐次拦截日志及设置刷新 |
| `DexIndex.java` | 读取 DEX 并建立所需的语义索引 |
| `CompatibilityResolver.java` | 精确配置、候选匹配和功能分组 |
| `ExtendedResolver.java` | GuardProvider 与 SystemHelper 的识别规则 |
| `tests/ResolverTest.java` | 识别规则的主机端测试 |
| `tools/run_resolver_tests.py` | 准备依赖并执行识别测试 |
| `tools/check_extended_resolver.py` | 用真实 APK 检查扩展作用域识别结果 |
| `tools/repack_apk.py` | 直接工具链的签名前组装与资源对齐检查 |

Java 源码位于 `app/src/main/java/io/github/yunyizea/xsofprivacy/`。

## 适配边界

- 拦截范围限于已经识别的路径，不代表覆盖 HyperOS 的全部数据采集或联网行为。
- 未识别的新增表、接口及其他组件不会自动受到保护。
- 方法内联、动态加载、native 实现、字符串加密和较大结构变化都可能导致匹配或拦截失效。
- 未知 APK 在目标进程初始化期间同步扫描，可能增加启动时间；日志记录耗时，但不同设备上的延迟、内存和长期稳定性仍需评估。
- DEX 格式不支持、单个 DEX 超过 96 MiB、累计超过 256 MiB 或解析失败时，停止识别；每个进程只尝试一次，失败后需要重启进程。
- 数据库不再增长不能单独证明不存在内存采集、其他存储位置或上传。模块也不据此判断原系统是否将数据提供给任何特定机构。

## 问题反馈

提交 Issue 时，请提供机型、完整系统版本、手机管家版本、模块版本、LSPosed 分支与版本，以及相关的 `XsofPrivacy` 日志。

如涉及某次操作，请说明复现步骤、预期结果、实际结果和是否能在停用模块后恢复。日志、截图或数据库片段中的个人信息请先脱敏；通常无需上传完整行为数据库。

## 0.3.0 扩展范围

新增 GuardProvider `guard.ai_detection` 1 组、1 个目标；SystemHelper 的许可判断、
加密 POST、应用统计线程和 7 类专用广播入口共 10 组、10 个目标。三个作用域
合计 25 组、39 个目标，日志在各进程分别汇总。

新增作用域同样支持已分析 APK 的哈希快速路径和未知 APK 的特征匹配路径。
专用 Receiver 还匹配组件类名，组件改名后会跳过，不保证所有未来版本兼容。
`helper.policy_gate` 只改变本进程中的返回结果，不修改手机保存的许可设置。
`helper.encrypted_post` 返回 false，不伪造成功；调用方可能重试，需检查实际开销。
`guard.ai_detection` 跳过启动命令、返回 START_NOT_STICKY 并请求 stopSelf(startId)。
若出现 `STOP_FAILED`，停止请求未成功，需检查实际服务状态。

这会关闭相关 AI 音视频反诈和运营商遥测功能，不是仅隐藏提示。GuardProvider
其他应用扫描/上报、未知 native 或动态加载路径仍可能运行，不代表全面阻断采集。

新增样本：GuardProvider `3.1.4-20260902.0`（330），SystemHelper
`3.0.1-20260313`（34）。分析证据、开关条件及限制见
[扩展分析记录](docs/extended-analysis.md)。

新增源码 `ExtendedResolver.java`，测试见 `tests/ExtendedResolverTest.java` 和
`tests/EXTENDED_RESULTS.txt`。可用下列命令同时运行两套主机识别测试：

```bash
python tools/run_resolver_tests.py securitycenter-12.8.7.apk guardprovider-3.1.4.apk systemhelper-3.0.1.apk
```

0.3.0 新增功能尚未实机验证。原有实机反馈不能直接用于新增功能的效果结论。
