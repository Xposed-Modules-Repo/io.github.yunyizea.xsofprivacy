# GuardProvider / SystemHelper 静态分析记录

分析日期：2026-11-05。依据使用者提供的原 APK；没有执行原 APK。
静态权限声明、代码路径和手机上的实际运行行为需要分开判断。

## 样本

| APK | versionName | versionCode |
|---|---|---:|
| com.miui.guardprovider | 3.1.4-20260902.0 | 330 |
| com.mobiletools.systemhelper | 3.0.1-20260313 | 34 |

SHA-256：

```text
GuardProvider
eff2c614d054263068e931f859f2e9fb4c66e31f960d815ab507abbdff15bb5d
SystemHelper
1de8d965e295db27e189aa179cdb45438d7f759cffbb43ce55f840b614ff6c65
```

使用者环境：小米 14，HyperOS 3.0.307.0.WNCCNXM.C11，LSPosed 2.2.1 (7912)。
新增 Hook 没有真机验证。

## GuardProvider

`com.miui.guardprovider.aiguard.AiGuardService.onStartCommand(Intent,int,int)`
处理 COMMAND、CAPABILITIES、PHONE_SCAM_SCENE 和 VIDEO_SCAM_SCENE。
命令 1 进入音频检测，命令 2 进入视频检测。存在通知构建和 startForeground；
电话音频分支也检查 RECORD_AUDIO 权限。不能仅凭这些代码确定手机上实际
显示了哪些提示，也不能把本版本直接描述为没有任何通知/授权处理。

视频分支通过混淆类 x7 调用录制对象，可见约 3 秒等待，随后将文件交给检测。
未检测出风险后存在约 2 秒等待再继续的路径；风险结果进入提醒和停止服务。
协程反编译的局部变量类型可能失真，关键常量、方法引用和签名同时对照 DEX。

`AiGuardService.e(Path,k20)` 读取文件，生成包含 streamName=clip.mp4、
fileBase64、requestId 的 JSON，交给 detectV2 相关保密计算接口处理。
Base64 是编码，不等于加密；后续包装接口涉及 EncryptedData。此方法不能
单独证明每次调用都产生网络请求，也不能确定最终服务地址及云端留存。

代码中存在温控停止、音频冲突处理，以及端侧/云侧检测相关配置。
这些机制的存在不能证明其动机是避免用户发现。

### 开关

命令 3 读取 ai_guard_function_switch，经 q7/h7 用于 daily_report 的
enable_status 等统计并停止本次服务。这个字段的已追踪用途不能当作
音视频检测总开关，也不能据此断言总开关无效。

PermissionRequestActivity.F() 检查 debug.config.media.video.voip.detect
和 ai_guard_projection_permission，存在提示及 CTA 处理。是否由其他入口
绕开、调用方如何决定启动命令，仍需结合调用方和实机状态核查。

### 新增拦截

跳过已识别 AI 服务的启动命令，返回 START_NOT_STICKY，调用 stopSelf(startId)。
保留 Service 生命周期，以便释放初始化资源。这会停用该服务的 AI 通话检测
及命令 3 的统计，不是仅隐藏通知。

不全局 Hook MediaRecorder/MediaProjection，不禁用整个 GuardProvider，
也不泛拦截 flash.sec.miui.com。另有 CollectPackagesAction、PackageUploadWorker
及 detect/app 相关应用检查/收集/上传实现，本次未将这些路径纳入拦截。
不能把 AI 服务拦截宣传为完整停止应用列表上报。

## SystemHelper

- e1.b.b() 组装设备 JSON，含 IMEI、ICCID、IMSI、型号、版本、网络和信号等字段。
  字段存在不代表每次都成功取得值。
- e1.f 使用 getInstalledApplications、UsageStatsManager、NetworkStatsManager
  汇总应用使用与流量信息。默认时间窗口配置为 86400000 ms，可被配置改变。
  前台时间组装时除以 60000，不能笼统说最终上传时长是毫秒精度。
- GetSignalInfoReceiver 有百度定位客户端启动路径，信号 JSON 含经纬度字段。
  权限和字段不能单独证明某次取得了精确位置。
- e1.g.a(e1.b) 组装发送内容；g1.f.b(String,byte[],byte[]) 执行 HTTP/HTTPS
  POST，Content-Type 为 application/encrypted-json。默认地址字符串为
  http://dm.wo.com.cn:18080/register。HTTP 地址与正文加密是两个问题。

### 存在实质性许可判断

g1.l.a(Context) 在初始化状态检查后执行：

```java
Settings.Secure.getInt(resolver, "operator_service_improve_plan", 0) == 1
```

默认读取值为 0。应用使用统计线程、当前记录发送线程、信号/位置 Receiver
存在 g1.d.e 状态检查，初始化和 Receiver 路径会更新该状态。
至少这些路径存在实质条件判断，不能从文章直接推导本版本关开关后仍全部照传。
是否所有采集受它控制、是否存在缓存和其他路径，仍需动态验证。

只读检查当前手机值：

```powershell
.\adb.exe shell settings get secure operator_service_improve_plan
```

### 新增拦截

- 将已识别许可判断的返回值限制为 false，不修改系统设置。
- 跳过已识别的应用使用统计线程 run。
- 跳过 7 类专用 Receiver 的 onReceive：启动、SIM、连接、应用、计划和信号事件。
- 将已识别加密 POST 返回为 false，不伪造成功，不改变全局网络。

终端注册、运营商体验计划和信号统计可能受到影响。其他组件的定位、native SDK
自身联网、历史数据库和未知备用入口不在完整覆盖保证内。

## 证据范围

测试确认特定方法的识别与 Hook 配置，没有对手机进行远程操作，也没有证明
这台手机每次通话都录制或某项数据已经上传。
新增精确配置和特征识别结果一致；错误包、证据缺失和多候选等场景均检查跳过。
实际安装、命中、停止效果、耗电和稳定性需要使用者验证。
