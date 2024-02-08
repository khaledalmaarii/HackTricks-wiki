# macOS MDM

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

**了解macOS MDM的相关内容：**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 基础知识

### **MDM（移动设备管理）概述**
[移动设备管理](https://en.wikipedia.org/wiki/Mobile_device_management)（MDM）用于管理智能手机、笔记本电脑和平板电脑等各种终端用户设备。特别是对于苹果的平台（iOS、macOS、tvOS），它涉及一组专门的功能、API和实践。MDM的运作依赖于一个兼容的MDM服务器，可以是商业可用的或开源的，并且必须支持[MDM协议](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。关键点包括：

- 对设备的集中控制。
- 依赖于遵循MDM协议的MDM服务器。
- MDM服务器能够向设备发送各种命令，例如远程数据擦除或配置安装。

### **DEP（设备注册计划）基础知识**
由苹果提供的[设备注册计划](https://www.apple.com/business/site/docs/DEP_Guide.pdf)（DEP）通过为iOS、macOS和tvOS设备提供零触摸配置，简化了移动设备管理（MDM）的集成。DEP自动化了注册过程，使设备可以在开箱即用时运行，几乎不需要用户或管理员干预。基本方面包括：

- 允许设备在初始激活时自动注册到预定义的MDM服务器。
- 主要适用于全新设备，但也适用于正在重新配置的设备。
- 简化设置，使设备迅速准备好供组织使用。

### **安全考虑**
需要注意的是，DEP提供的便捷注册方式虽然有益，但也可能带来安全风险。如果对MDM注册未充分实施保护措施，攻击者可能利用这一简化流程，在组织的MDM服务器上注册其设备，伪装成企业设备。

{% hint style="danger" %}
**安全警报**：简化的DEP注册可能允许未经授权的设备注册到组织的MDM服务器，如果没有适当的保护措施。
{% endhint %}

### **SCEP（简单证书注册协议）是什么？**

* 一种相对较旧的协议，在TLS和HTTPS普及之前创建。
* 为客户端提供了一种标准化的方式发送**证书签名请求**（CSR）以获得证书。客户端将要求服务器给他签名的证书。

### **什么是配置文件（也称为mobileconfigs）？**

* 苹果官方的**设置/强制系统配置**的方式。
* 可以包含多个有效负载的文件格式。
* 基于属性列表（XML类型）。
* “可以签名和加密以验证其来源、确保其完整性并保护其内容。” 基础知识 — iOS安全指南，2018年1月。

## 协议

### MDM

* APNs（**苹果服务器**）+ RESTful API（**MDM供应商**服务器）的组合
* **通信**发生在与**设备管理产品**相关的设备和服务器之间
* 从MDM传递到设备的**命令以plist编码的字典**
* 全部通过**HTTPS**。MDM服务器可以（通常）进行固定。
* 苹果授予MDM供应商一个**APNs证书**用于身份验证

### DEP

* **3个API**：1用于经销商，1用于MDM供应商，1用于设备标识（未记录）：
* 所谓的[DEP“云服务”API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。MDM服务器使用此API将DEP配置文件与特定设备关联。
* [由苹果授权经销商使用的DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)用于注册设备、检查注册状态和检查交易状态。
* 未记录的私有DEP API。苹果设备使用此API请求其DEP配置文件。在macOS上，`cloudconfigurationd`二进制文件负责通过此API进行通信。
* 更现代化，基于**JSON**（而不是plist）
* 苹果向MDM供应商授予一个**OAuth令牌**

**DEP“云服务”API**

* RESTful
* 从苹果同步设备记录到MDM服务器
* 将“DEP配置文件”从MDM服务器同步到苹果（稍后由苹果传递给设备）
* DEP“配置文件”包含：
* MDM供应商服务器URL
* 用于服务器URL的额外受信任证书（可选固定）
* 额外设置（例如在设置助手中跳过哪些屏幕）

## 序列号

2010年后生产的苹果设备通常具有**12个字符的字母数字**序列号，前三位代表制造地点，接下来的两位表示制造年份和周数，接下来的三位提供唯一标识符，最后四位表示型号号码。

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## 注册和管理步骤

1. 设备记录创建（经销商、苹果）：为新设备创建记录
2. 设备记录分配（客户）：将设备分配给MDM服务器
3. 设备记录同步（MDM供应商）：MDM同步设备记录并将DEP配置文件推送到苹果
4. DEP签到（设备）：设备获取其DEP配置文件
5. 配置文件检索（设备）
6. 配置文件安装（设备） a. 包括MDM、SCEP和根CA有效负载
7. MDM命令发出（设备）

![](<../../../.gitbook/assets/image (564).png>)

文件`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd`导出的函数可以被视为注册过程的**高级“步骤”**。

### 步骤4：DEP签到 - 获取激活记录

此过程发生在**用户首次启动Mac**（或完全擦除后）

![](<../../../.gitbook/assets/image (568).png>)

或执行`sudo profiles show -type enrollment`

* 确定**设备是否启用DEP**
* 激活记录是DEP“配置文件”的内部名称
* 一旦设备连接到互联网，即开始
* 由**`CPFetchActivationRecord`**驱动
* 通过XPC由**`cloudconfigurationd`**实现。**“设置助手”**（设备首次启动时）或**`profiles`**命令将**联系此守护程序**以检索激活记录。
* LaunchDaemon（始终以root身份运行）

它遵循由**`MCTeslaConfigurationFetcher`**执行的几个获取激活记录的步骤。此过程使用一种称为**Absinthe**的加密

1. 检索**证书**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. 从证书初始化状态（**`NACInit`**）
1. 使用各种设备特定数据（例如通过`IOKit`获取的**序列号**）
3. 检索**会话密钥**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. 建立会话（**`NACKeyEstablishment`**）
5. 发送请求
1. 发送到[https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)发送数据`{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON有效负载使用Absinthe进行加密（**`NACSign`**）
3. 所有请求均通过HTTPS，使用内置根证书

![](<../../../.gitbook/assets/image (566).png>)

响应是一个包含一些重要数据的JSON字典，例如：

* **url**：激活配置文件的MDM供应商主机的URL
* **anchor-certs**：用作受信任锚点的DER证书数组

### **步骤5：配置文件检索**

![](<../../../.gitbook/assets/image (567).png>)

* 发送请求到DEP配置文件中提供的**URL**。
* 如果提供，将使用**锚点证书**来**评估信任**。
* 提醒：DEP配置文件的**anchor\_certs**属性
* 请求是一个包含设备标识的简单.plist
* 示例：**UDID、OS版本**。
* CMS签名，DER编码
* 使用**设备身份证书（来自APNS）**进行签名
* **证书链**包括已过期的**Apple iPhone设备CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (7).png>)

### 步骤6：配置文件安装

* 检索后，**配置文件存储在系统上**
* 如果在**设置助手**中，此步骤将自动开始
* 由**`CPInstallActivationProfile`**驱动
* 由mdmclient通过XPC实现
* LaunchDaemon（作为root）或LaunchAgent（作为用户），取决于上下文
* 配置文件具有多个要安装的有效负载
* 框架具有基于插件的架构用于安装配置文件
* 每种有效负载类型与插件相关联
* 可以是XPC（在框架中）或经典的Cocoa（在ManagedClient.app中）
* 例如：
* 证书有效负载使用CertificateService.xpc

通常，由MDM供应商提供的**激活配置文件**将**包含以下有效负载**：

* `com.apple.mdm`：用于在MDM中**注册**设备
* `com.apple.security.scep`：用于向设备安全地提供**客户端证书**。
* `com.apple.security.pem`：将**受信任的CA证书**安装到设备的系统钥匙串中。
* 安装MDM有效负载相当于文档中的**MDM签到**
* 有效负载**包含关键属性**：
*
* MDM签到URL（**`CheckInURL`**）
* MDM命令轮询URL（**`ServerURL`**）+ 触发它的APNs主题
* 要安装MDM有效负载，将请求发送到**`CheckInURL`**
* 由**`mdmclient`**实现
* MDM有效负载可能依赖于其他有效负载
* 允许**请求固定到特定证书**：
* 属性：**`CheckInURLPinningCertificateUUIDs`**
* 属性：**`ServerURLPinningCertificateUUIDs`**
* 通过PEM有效负载交付
* 允许设备具有身份证书：
* 属性：IdentityCertificateUUID
* 通过SCEP有效负载交付

### **步骤7：监听MDM命令**

* 在MDM签到完成后，供应商可以使用APNs**发出推送通知**
* 收到后，由**`mdmclient`**处理
* 为了轮询MDM命令，将请求发送到ServerURL
* 利用先前安装的MDM有效负载：
* **`ServerURLPinningCertificateUUIDs`**用于固定请求
* **`IdentityCertificateUUID`**用于TLS客户端证书

## 攻击

### 将设备注册到其他组织

如前所述，为了尝试将设备注册到组织中，**只需要一个属于该组织的序列号**。一旦设备注册，多个组织将在新设备上安装敏感数据：证书、应用程序、WiFi密码、VPN配置[等等](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。因此，如果注册过程未受到正确保护，这可能是攻击者的危险入口点：

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}


<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection
