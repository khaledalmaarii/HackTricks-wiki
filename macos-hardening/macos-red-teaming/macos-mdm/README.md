# macOS MDM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基础知识

### 什么是移动设备管理（MDM）？

[移动设备管理](https://en.wikipedia.org/wiki/Mobile\_device\_management)（MDM）是一种常用的技术，用于**管理终端用户计算设备**，如手机、笔记本电脑、台式机和平板电脑。在苹果平台（如iOS、macOS和tvOS）中，它指的是一组特定的功能、API和技术，管理员可以使用这些功能来管理这些设备。通过MDM管理设备需要一个兼容的商业或开源MDM服务器，该服务器实现了对[MDM协议](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)的支持。

* 实现**集中式设备管理**的一种方法
* 需要一个实现了MDM协议支持的**MDM服务器**
* MDM服务器可以发送MDM命令，如远程擦除或“安装此配置”

### 基础知识 什么是设备注册计划（DEP）？

[设备注册计划](https://www.apple.com/business/site/docs/DEP\_Guide.pdf)（DEP）是由苹果提供的一项服务，通过提供对iOS、macOS和tvOS设备的**零触摸配置**，**简化**了移动设备管理（MDM）的**注册**过程。与传统的部署方法不同，传统的部署方法需要最终用户或管理员采取行动来配置设备，或者手动与MDM服务器进行注册，DEP旨在引导这个过程，**使用户能够打开新的苹果设备并立即将其配置为在组织中使用**。

管理员可以利用DEP自动将设备注册到组织的MDM服务器。一旦设备注册成功，**在许多情况下，它被视为组织拥有的“可信任”设备**，可以接收任意数量的证书、应用程序、WiFi密码、VPN配置等[等等](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。

* 允许设备在首次启动时自动注册到预配置的MDM服务器
* 设备**全新**时最有用
* 对于**重新配置**工作流程（使用全新的操作系统进行擦除）也很有用

{% hint style="danger" %}
不幸的是，如果组织没有采取额外措施来**保护其MDM注册**，通过DEP简化的最终用户注册过程也意味着攻击者可以简化地将自己选择的设备注册到组织的MDM服务器中，假冒企业设备的“身份”。
{% endhint %}

### 基础知识 什么是简单证书注册协议（SCEP）？

* 一种相对较旧的协议，在TLS和HTTPS广泛使用之前创建的。
* 为客户端提供了一种标准化的方式，用于发送**证书签名请求**（CSR），以便获得证书。客户端将要求服务器给他签名的证书。

### 什么是配置文件（也称为mobileconfigs）？

* 苹果官方的**设置/强制系统配置**的方式。
* 可以包含多个有效负载的文件格式。
* 基于属性列表（XML类型）。
* “可以签名和加密，以验证其来源、确保其完整性并保护其内容。” 基础知识 — 第70页，iOS安全指南，2018年1月。

## 协议

### MDM

* APNs（**苹果服务器**）+ RESTful API（**MDM供应商**服务器）的组合
* 通信发生在与设备管理产品相关的设备和服务器之间
* **命令**以plist编码的字典形式从MDM传递到设备
* 全部使用**HTTPS**。MDM服务器可以（通常）进行固定。
* 苹果向MDM供应商授予APNs证书进行身份验证

### DEP

* **3个API**：1个用于经销商，1个用于MDM供应商，1个用于设备身份（未记录）：
* 所谓的[DEP“云服务”API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。这是MDM服务器用于将DEP配置文件与特定设备关联的API。
* [由苹果授权经销商使用的DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)，用于注册设备、检查注册状态和检查交易状态。
* 未记录的私有DEP API。苹果设备使用此API请求其DEP配置文件。在macOS上，`cloudconfigurationd`二进制文件负责通过此API进行通信。
* 更现代化，基于**JSON**（而不是plist）
* 苹果向MDM供应商授予OAuth令牌

**DEP“云服务”API**

* RESTful
* 将设备记录从苹果同步到MDM服务器
* 将“DEP配置文件”从MDM服务器同步到苹果（稍后由苹果传递给设备）
* DEP“配置文件”包含：
* MDM供应商服务器URL
* 用于服务器URL的其他受信任证书（可选固定）
* 额外设置（例如，在设置助理中跳过哪些屏幕）
## 序列号

2010年后生产的苹果设备通常具有**12个字符的字母数字**序列号，其中**前三位表示制造地点**，接下来的**两位**表示**年份**和**生产周**，接下来的**三位**提供一个**唯一标识符**，最后的**四位**表示**型号号码**。

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## 注册和管理步骤

1. 设备记录创建（经销商，苹果）：创建新设备的记录
2. 设备记录分配（客户）：将设备分配给MDM服务器
3. 设备记录同步（MDM供应商）：MDM同步设备记录并将DEP配置文件推送到苹果
4. DEP签到（设备）：设备获取其DEP配置文件
5. 配置文件检索（设备）
6. 配置文件安装（设备）a. 包括MDM，SCEP和根CA负载
7. MDM命令发出（设备）

![](<../../../.gitbook/assets/image (564).png>)

文件`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd`导出了可以被视为注册过程的**高级“步骤”**的函数。

### 步骤4：DEP签到 - 获取激活记录

这个过程发生在**用户首次启动Mac**（或完全擦除后）

![](<../../../.gitbook/assets/image (568).png>)

或者在执行`sudo profiles show -type enrollment`时

* 确定设备是否启用DEP
* 激活记录是DEP的内部名称“配置文件”
* 一旦设备连接到互联网，就会开始
* 由**`CPFetchActivationRecord`**驱动
* 通过XPC由**`cloudconfigurationd`**实现。**“设置助手”**（设备首次启动时）或**`profiles`**命令将**联系此守护进程**以检索激活记录。
* LaunchDaemon（始终以root身份运行）

它按照由**`MCTeslaConfigurationFetcher`**执行的几个步骤来获取激活记录。此过程使用一种称为**Absinthe**的加密方法。

1. 检索**证书**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. 从证书初始化状态（**`NACInit`**）
1. 使用各种设备特定数据（例如通过`IOKit`获取的**序列号**）
3. 检索**会话密钥**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. 建立会话（**`NACKeyEstablishment`**）
5. 发送请求
1. POST到[https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)，发送数据`{ "action": "RequestProfileConfiguration", "sn": "" }`
2. 使用Absinthe对JSON有效负载进行加密（**`NACSign`**）
3. 所有请求都通过HTTPs进行，使用内置根证书

![](<../../../.gitbook/assets/image (566).png>)

响应是一个包含一些重要数据的JSON字典，例如：

* **url**：激活配置文件的MDM供应商主机的URL
* **anchor-certs**：用作受信任锚点的DER证书数组

### **步骤5：配置文件检索**

![](<../../../.gitbook/assets/image (567).png>)

* 发送请求到DEP配置文件中提供的**URL**。
* 如果提供了，将使用**锚点证书**来**评估信任**。
* 提醒：DEP配置文件的**anchor\_certs**属性
* 请求是一个带有设备标识的简单的.plist文件
* 示例：**UDID，操作系统版本**。
* CMS签名，DER编码
* 使用**设备身份证书（来自APNS）**进行签名
* **证书链**包括已过期的**Apple iPhone Device CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (7).png>)

### 步骤6：配置文件安装

* 一旦检索到，**配置文件将存储在系统上**
* 如果在**设置助手**中，此步骤将自动开始
* 由**`CPInstallActivationProfile`**驱动
* 通过XPC由mdmclient实现
* LaunchDaemon（作为root）或LaunchAgent（作为用户），取决于上下文
* 配置文件具有多个要安装的负载
* 框架具有基于插件的架构来安装配置文件
* 每个负载类型与一个插件相关联
* 可以是XPC（在框架中）或经典的Cocoa（在ManagedClient.app中）
* 示例：
* 证书负载使用CertificateService.xpc

通常，由MDM供应商提供的**激活配置文件**将包括以下负载：

* `com.apple.mdm`：用于将设备**注册**到MDM
* `com.apple.security.scep`：用于向设备**安全地提供客户端证书**。
* `com.apple.security.pem`：用于将**受信任的CA证书**安装到设备的系统钥匙串中。
* 安装与文档中的**MDM签到**等效的MDM负载
* 负载包含关键属性：
*
* MDM签到URL（**`CheckInURL`**）
* MDM命令轮询URL（**`ServerURL`**）+ APNs主题以触发它
* 要安装MDM负载，发送请求到**`CheckInURL`**
* 在**`mdmclient`**中实现
* MDM负载可以依赖其他负载
* 允许**请求固定到特定证书**：
* 属性：**`CheckInURLPinningCertificateUUIDs`**
* 属性：**`ServerURLPinningCertificateUUIDs`**
* 通过PEM负载传递
* 允许设备与身份证书关联：
* 属性：IdentityCertificateUUID
* 通过SCEP负载传递
### **步骤 7：监听 MDM 命令**

* 在 MDM 检查完成后，供应商可以使用 APNs 发送推送通知
* 收到推送通知后，由 `mdmclient` 处理
* 为了轮询 MDM 命令，会向 ServerURL 发送请求
* 使用之前安装的 MDM 负载：
* `ServerURLPinningCertificateUUIDs` 用于固定请求
* `IdentityCertificateUUID` 用于 TLS 客户端证书

## 攻击

### 将设备注册到其他组织

如前所述，为了尝试将设备注册到组织中，只需要一个属于该组织的序列号。一旦设备注册成功，多个组织将在新设备上安装敏感数据：证书、应用程序、WiFi 密码、VPN 配置[等等](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。因此，如果注册过程没有得到正确保护，这可能成为攻击者的危险入口：

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

## **参考资料**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？想要在 HackTricks 中 **为你的公司做广告** 吗？或者你想要访问 **PEASS 的最新版本或下载 PDF 格式的 HackTricks** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
