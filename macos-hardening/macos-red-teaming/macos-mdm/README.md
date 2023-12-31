# macOS MDM

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 基础知识

### 什么是MDM（移动设备管理）？

[移动设备管理](https://en.wikipedia.org/wiki/Mobile\_device\_management)（MDM）是一种常用的技术，用于**管理终端用户计算设备**，如手机、笔记本电脑、台式机和平板电脑。在苹果平台，如iOS、macOS和tvOS，它指的是管理员用来管理这些设备的一组特定功能、API和技术。通过MDM管理设备需要一个兼容的商业或开源MDM服务器，该服务器实现了对[MDM协议](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)的支持。

* 实现**集中式设备管理**的一种方式
* 需要一个**MDM服务器**，它实现了对MDM协议的支持
* MDM服务器可以**发送MDM命令**，例如远程擦除或“安装此配置”

### 基础知识 什么是DEP（设备注册计划）？

[设备注册计划](https://www.apple.com/business/site/docs/DEP\_Guide.pdf)（DEP）是苹果提供的一项服务，通过提供iOS、macOS和tvOS设备的**零触摸配置**，**简化**了移动设备管理（MDM）**注册**。与更传统的部署方法不同，后者需要终端用户或管理员采取行动配置设备或手动注册MDM服务器，DEP旨在引导此过程，**允许用户打开新的苹果设备包装并几乎立即为组织使用配置好**。

管理员可以利用DEP自动将设备注册到组织的MDM服务器。一旦设备注册，**在许多情况下，它被视为组织拥有的“受信任”**设备，并可能接收任意数量的证书、应用程序、WiFi密码、VPN配置[等等](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。

* 允许设备在**首次开机**时自动注册预配置的MDM服务器
* 当**设备**是**全新**的时候最有用
* 对于**重新配置**工作流程也很有用（用新安装的操作系统**擦除**）

{% hint style="danger" %}
不幸的是，如果组织没有采取额外措施来**保护他们的MDM注册**，通过DEP简化的终端用户注册过程也意味着攻击者注册他们选择的设备到组织的MDM服务器的过程同样简化，假设企业设备的“身份”。
{% endhint %}

### 基础知识 什么是SCEP（简单证书注册协议）？

* 一个相对较老的协议，在TLS和HTTPS广泛使用之前创建。
* 为客户端提供了一种标准化的方式发送**证书签名请求**（CSR），以获得证书。客户端将请求服务器给他签发一个证书。

### 什么是配置文件（又名mobileconfigs）？

* 苹果官方的**设置/强制系统配置**方式。
* 可以包含多个有效载荷的文件格式。
* 基于属性列表（XML类型）。
* “可以签名和加密以验证其来源，确保其完整性，并保护其内容。”基础知识 — 第70页，iOS安全指南，2018年1月。

## 协议

### MDM

* APNs（**苹果服务器**）+ RESTful API（**MDM** **供应商**服务器）的组合
* **通信**发生在**设备**和与**设备管理**产品相关联的服务器之间
* **命令**通过**plist编码的字典**从MDM传送到设备
* 全部通过**HTTPS**。MDM服务器可以（通常是）固定。
* 苹果授予MDM供应商一个**APNs证书**进行认证

### DEP

* **3个API**：1个给经销商，1个给MDM供应商，1个给设备身份（未记录）：
* 所谓的[DEP "云服务" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。这是MDM服务器用来将DEP配置文件与特定设备关联的。
* [苹果授权经销商使用的DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)用于注册设备，检查注册状态和检查交易状态。
* 未记录的私有DEP API。这是苹果设备用来请求其DEP配置文件的。在macOS上，`cloudconfigurationd`二进制文件负责通过此API进行通信。
* 更现代且基于**JSON**（与plist相比）
* 苹果授予MDM供应商一个**OAuth令牌**

**DEP "云服务" API**

* RESTful
* 从苹果同步设备记录到MDM服务器
* 从MDM服务器同步“DEP配置文件”到苹果（稍后由苹果交付给设备）
* DEP“配置文件”包含：
* MDM供应商服务器URL
* 服务器URL的额外受信任证书（可选固定）
* 额外设置（例如，在设置助手中跳过哪些屏幕）

## 序列号

2010年之后生产的苹果设备通常具有**12个字符的字母数字**序列号，**前三位代表制造地点**，接下来的**两位**表示制造的**年份**和**周**，接下来的**三位**提供一个**唯一的** **标识符**，最后的**四位**代表**型号编号**。

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## 注册和管理的步骤

1. 设备记录创建（经销商，苹果）：创建新设备的记录
2. 设备记录分配（客户）：将设备分配给MDM服务器
3. 设备记录同步（MDM供应商）：MDM同步设备记录并将DEP配置文件推送到苹果
4. DEP签到（设备）：设备获取其DEP配置文件
5. 配置文件检索（设备）
6. 配置文件安装（设备）a. 包括MDM、SCEP和根CA有效载荷
7. MDM命令发出（设备）

![](<../../../.gitbook/assets/image (564).png>)

文件`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd`导出的函数可以被认为是注册过程的**高级"步骤"**。

### 第4步：DEP签到 - 获取激活记录

这部分过程发生在**用户首次启动Mac**（或完全擦除后）

![](<../../../.gitbook/assets/image (568).png>)

或执行`sudo profiles show -type enrollment`

* 确定**设备是否启用了DEP**
* 激活记录是**DEP“配置文件”**的内部名称
* 一旦设备连接到互联网就开始
* 由**`CPFetchActivationRecord`**驱动
* 由**`cloudconfigurationd`**通过XPC实现。**"设置助手"**（当设备首次启动时）或**`profiles`**命令将**联系此守护进程**以检索激活记录。
* LaunchDaemon（始终以root身份运行）

它遵循几个步骤来获取激活记录，由**`MCTeslaConfigurationFetcher`**执行。这个过程使用了一种称为**Absinthe**的加密

1. 检索**证书**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. 从证书初始化状态（**`NACInit`**）
1. 使用各种设备特定数据（即通过`IOKit`的**序列号**）
3. 检索**会话密钥**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. 建立会话（**`NACKeyEstablishment`**）
5. 发出请求
1. POST到[https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)发送数据`{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON有效载荷使用Absinthe加密（**`NACSign`**）
3. 所有请求通过HTTPs，使用内置根证书

![](<../../../.gitbook/assets/image (566).png>)

响应是一个包含一些重要数据的JSON字典，如：

* **url**：MDM供应商主机的激活配置文件的URL
* **anchor-certs**：用作受信任锚点的DER证书数组

### **第5步：配置文件检索**

![](<../../../.gitbook/assets/image (567).png>)

* 发送请求到DEP配置文件中提供的**url**。
* 如果提供，使用**锚点证书**来**评估信任**。
* 提醒：DEP配置文件的**anchor\_certs**属性
* **请求是一个简单的.plist**，带有设备识别信息
* 示例：**UDID，操作系统版本**。
* CMS签名，DER编码
* 使用**设备身份证书（来自APNS）**签名
* **证书链**包括过期的**苹果iPhone设备CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1. (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (
