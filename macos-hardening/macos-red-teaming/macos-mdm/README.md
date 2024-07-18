# macOS MDM

{% hint style="success" %}
学习并练习AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

**了解 macOS MDM 的内容：**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 基础知识

### **MDM（移动设备管理）概述**

[移动设备管理](https://en.wikipedia.org/wiki/Mobile\_device\_management)（MDM）用于管理智能手机、笔记本电脑和平板电脑等多种终端用户设备。特别是对于苹果的平台（iOS、macOS、tvOS），它涉及一组专门的功能、API 和实践。MDM 的运作依赖于兼容的 MDM 服务器，该服务器可以是商业可用的或开源的，并且必须支持[MDM 协议](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。关键点包括：

* 对设备的集中控制。
* 依赖于遵循 MDM 协议的 MDM 服务器。
* MDM 服务器能够向设备发送各种命令，例如远程数据擦除或配置安装。

### **DEP（设备注册计划）基础知识**

由苹果提供的[设备注册计划](https://www.apple.com/business/site/docs/DEP\_Guide.pdf)（DEP）通过为 iOS、macOS 和 tvOS 设备提供零触摸配置，简化了移动设备管理（MDM）的集成。DEP 自动化了注册过程，使设备可以在开箱即用时运行，几乎不需要用户或管理员干预。基本方面包括：

* 允许设备在初始激活时自动向预定义的 MDM 服务器注册。
* 主要有利于全新设备，但也适用于正在重新配置的设备。
* 简化设置，使设备迅速准备好供组织使用。

### **安全考虑**

需要注意的是，DEP 提供的便捷注册方式虽然有利，但也可能带来安全风险。如果对 MDM 注册未充分执行保护措施，攻击者可能利用这一简化流程，在组织的 MDM 服务器上注册其设备，伪装成公司设备。

{% hint style="danger" %}
**安全警报**：简化的 DEP 注册可能允许未经授权的设备在组织的 MDM 服务器上注册，如果没有适当的保护措施。
{% endhint %}

### **SCEP（简单证书注册协议）是什么？**

* 一个相对古老的协议，在 TLS 和 HTTPS 广泛使用之前创建。
* 为客户端提供了一种标准化的方式发送**证书签名请求**（CSR）以获得证书。客户端将要求服务器给他签名的证书。

### 什么是配置文件（也称为 mobileconfigs）？

* 苹果官方的**设置/强制系统配置**的方式。
* 可以包含多个有效负载的文件格式。
* 基于属性列表（XML 类型）。
* “可以签名和加密以验证其来源、确保其完整性并保护其内容。” 基础知识 — iOS 安全指南，2018 年 1 月，第 70 页。

## 协议

### MDM

* APNs（**苹果服务器**）+ RESTful API（**MDM** **供应商**服务器）的组合
* 通信发生在与**设备** **管理** **产品**相关的设备和服务器之间
* 从 MDM 传递到设备的**命令**以**plist 编码的字典**形式传递
* 全部通过**HTTPS**。MDM 服务器可以（通常）被固定。
* 苹果授予 MDM 供应商一个**APNs 证书**用于身份验证

### DEP

* **3 个 API**：1 用于经销商，1 用于 MDM 供应商，1 用于设备标识（未记录）：
* 所谓的[DEP “云服务” API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。MDM 服务器使用此 API 将 DEP 配置文件与特定设备关联。
* [由苹果授权经销商使用的 DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) 用于注册设备、检查注册状态和检查交易状态。
* 未记录的私有 DEP API。苹果设备使用此 API 请求其 DEP 配置文件。在 macOS 上，`cloudconfigurationd` 二进制文件负责通过此 API 进行通信。
* 更现代化，基于**JSON**（与 plist 相比）
* 苹果授予 MDM 供应商一个**OAuth 令牌**

**DEP “云服务” API**

* RESTful
* 从苹果同步设备记录到 MDM 服务器
* 将“DEP 配置文件”从 MDM 服务器同步到苹果（稍后由苹果传递给设备）
* DEP “配置文件”包含：
* MDM 供应商服务器 URL
* 用于服务器 URL 的额外受信任证书（可选固定）
* 额外设置（例如在设置助手中跳过哪些屏幕）

## 序列号

2010 年后制造的苹果设备通常具有**12 个字符的字母数字**序列号，**前三位表示制造地点**，接下来的**两位表示制造年份和周数**，接下来的**三位提供唯一标识符**，最后的**四位表示型号号码**。

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## 注册和管理步骤

1. 设备记录创建（经销商，苹果）：创建新设备的记录
2. 设备记录分配（客户）：将设备分配给 MDM 服务器
3. 设备记录同步（MDM 供应商）：MDM 同步设备记录并将 DEP 配置文件推送到苹果
4. DEP 登记（设备）：设备获取其 DEP 配置文件
5. 配置文件检索（设备）
6. 配置文件安装（设备）a. 包括 MDM、SCEP 和根 CA 负载
7. MDM 命令发出（设备）

![](<../../../.gitbook/assets/image (694).png>)

文件`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` 导出的函数可以被视为注册过程的**高级“步骤”**。
### 步骤 4: DEP 检查 - 获取激活记录

这个过程发生在**用户第一次启动 Mac**（或完全擦除后）

![](<../../../.gitbook/assets/image (1044).png>)

或执行 `sudo profiles show -type enrollment`

* 确定设备是否启用了**DEP**
* 激活记录是**DEP“配置文件”的内部名称**
* 一旦设备连接到互联网，就会开始
* 由**`CPFetchActivationRecord`**驱动
* 通过 XPC 由**`cloudconfigurationd`**实现。**“设置助手”**（设备首次启动时）或**`profiles`**命令将**联系此守护程序**以检索激活记录。
* LaunchDaemon（始终以 root 运行）

获取激活记录的过程由**`MCTeslaConfigurationFetcher`**执行，使用一种名为**Absinthe**的加密

1. 检索**证书**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. 从证书**初始化**状态（**`NACInit`）
1. 使用各种设备特定数据（例如**通过 `IOKit` 获取序列号**）
3. 检索**会话密钥**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. 建立会话（**`NACKeyEstablishment`）
5. 发送请求
1. POST 到 [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) 发送数据 `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON 负载使用 Absinthe 进行加密（**`NACSign`**）
3. 所有请求均通过 HTTPs，使用内置根证书

![](<../../../.gitbook/assets/image (566) (1).png>)

响应是一个包含一些重要数据的 JSON 字典，例如：

* **url**：MDM 供应商主机的激活配置文件的 URL
* **anchor-certs**：用作受信任锚点的 DER 证书数组

### **步骤 5: 检索配置文件**

![](<../../../.gitbook/assets/image (444).png>)

* 发送请求到**DEP 配置文件中提供的 URL**。
* 如果提供，将使用**锚点证书**来**评估信任**。
* 提醒：DEP 配置文件的**anchor\_certs**属性
* 请求是一个包含设备标识的简单 .plist
* 例如：**UDID、OS 版本**。
* CMS 签名，DER 编码
* 使用**设备身份证书（来自 APNS）**进行签名
* **证书链**包括已过期的**Apple iPhone Device CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### 步骤 6: 配置文件安装

* 一旦检索到，**配置文件将存储在系统中**
* 如果在**设置助手**中，此步骤将自动开始
* 由**`CPInstallActivationProfile`**驱动
* 通过 XPC 由 mdmclient 实现
* LaunchDaemon（作为 root）或 LaunchAgent（作为用户），取决于上下文
* 配置文件具有多个要安装的有效负载
* 框架具有基于插件的架构来安装配置文件
* 每种有效负载类型都与一个插件相关联
* 可以是 XPC（在框架中）或经典的 Cocoa（在 ManagedClient.app 中）
* 例如：
* 证书有效负载使用 CertificateService.xpc

通常，由 MDM 供应商提供的**激活配置文件**将包括以下有效负载：

* `com.apple.mdm`：用于**将设备注册到 MDM**
* `com.apple.security.scep`：用于向设备安全地提供**客户端证书**。
* `com.apple.security.pem`：用于向设备的系统钥匙串**安装受信任的 CA 证书**。
* 安装 MDM 有效负载相当于**文档中的 MDM 检查**
* 有效负载**包含关键属性**：
*
* MDM 检查 URL（**`CheckInURL`**）
* MDM 命令轮询 URL（**`ServerURL`**）+ 触发它的 APNs 主题
* 要安装 MDM 有效负载，将请求发送到**`CheckInURL`**
* 由**`mdmclient`**实现
* MDM 有效负载可能依赖于其他有效负载
* 允许**请求固定到特定证书**：
* 属性：**`CheckInURLPinningCertificateUUIDs`**
* 属性：**`ServerURLPinningCertificateUUIDs`**
* 通过 PEM 有效负载传递
* 允许设备关联身份证书：
* 属性：IdentityCertificateUUID
* 通过 SCEP 有效负载传递

### **步骤 7: 监听 MDM 命令**

在完成 MDM 检查后，供应商可以使用 APNs **发出推送通知**
收到后，由**`mdmclient`**处理
为了轮询 MDM 命令，将请求发送到 ServerURL
利用先前安装的 MDM 有效负载：
**`ServerURLPinningCertificateUUIDs`**用于固定请求
**`IdentityCertificateUUID`**用于 TLS 客户端证书

## 攻击

### 将设备注册到其他组织

如前所述，为了尝试将设备注册到一个组织中，只需要一个属于该组织的**序列号**。一旦设备注册，多个组织将在新设备上安装敏感数据：证书、应用程序、WiFi 密码、VPN 配置[等等](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。\
因此，如果注册过程没有得到正确保护，这可能是攻击者的一个危险入口：
