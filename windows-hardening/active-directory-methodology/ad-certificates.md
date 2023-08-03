# AD证书

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基本信息

### 证书的组成部分

* **主题** - 证书的所有者。
* **公钥** - 将主题与单独存储的私钥关联起来。
* **NotBefore和NotAfter日期** - 定义证书的有效期。
* **序列号** - CA分配给证书的标识符。
* **颁发者** - 标识颁发证书的人（通常是CA）。
* **SubjectAlternativeName** - 定义主题可能使用的一个或多个备用名称。 (_请参阅下文_)
* **基本约束** - 标识证书是CA还是终端实体，并在使用证书时是否存在任何限制。
* **扩展密钥用途（EKUs）** - 描述证书将如何使用的对象标识符（OID）。在Microsoft的术语中，也称为Enhanced Key Usage。常见的EKU OID包括：
* 代码签名（OID 1.3.6.1.5.5.7.3.3）- 证书用于签署可执行代码。
* 加密文件系统（OID 1.3.6.1.4.1.311.10.3.4）- 证书用于加密文件系统。
* 安全电子邮件（1.3.6.1.5.5.7.3.4）- 证书用于加密电子邮件。
* 客户端身份验证（OID 1.3.6.1.5.5.7.3.2）- 证书用于对另一个服务器（例如AD）进行身份验证。
* 智能卡登录（OID 1.3.6.1.4.1.311.20.2.2）- 证书用于智能卡身份验证。
* 服务器身份验证（OID 1.3.6.1.5.5.7.3.1）- 证书用于标识服务器（例如HTTPS证书）。
* **签名算法** - 指定用于签署证书的算法。
* **签名** - 使用颁发者（例如CA）的私钥对证书主体进行签名。

#### 主题备用名称

**主题备用名称**（SAN）是X.509v3扩展。它允许将**附加标识**绑定到**证书**。例如，如果一个Web服务器托管**多个域的内容**，则每个适用的**域**都可以在**SAN**中包含，以便Web服务器只需要一个HTTPS证书。

默认情况下，在基于证书的身份验证期间，AD根据SAN中指定的UPN将证书映射到用户帐户。如果攻击者在请求启用客户端身份验证的证书时可以**指定任意SAN**，并且CA使用攻击者提供的SAN创建和签署证书，则攻击者可以成为域中的任何用户。

### CA

AD CS在`CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`容器下的四个位置定义了AD林信任的CA证书，每个位置的目的不同：

* **Certification Authorities**容器定义了**受信任的根CA证书**。这些CA位于PKI树层次结构的顶部，是AD CS环境中的信任基础。每个CA都表示为容器内的AD对象，其中**objectClass**设置为**`certificationAuthority`**，**`cACertificate`**属性包含CA证书的**字节**。Windows将这些CA证书传播到每台Windows机器上的受信任的根证书颁发机构存储区。为了使AD将证书视为**受信任**，证书的信任**链**必须最终**以其中一个根CA**在此容器中定义的**结束**。
* **Enrolment Services**容器定义了每个**企业CA**（即在AD CS中启用了企业CA角色的CA）。每个企业CA都有一个AD对象，具有以下属性：
* **objectClass**属性设置为**`pKIEnrollmentService`**
* **`cACertificate`**属性包含CA证书的**字节**
* **`dNSHostName`**属性设置CA的**DNS主机名**
* **certificateTemplates**字段定义了**启用的证书模板**。证书模板是创建证书时CA使用的设置的“蓝图”，包括EKU、注册权限、证书的过期时间、签发要求和加密设置等。我们将在后面更详细地讨论证书模板。

{% hint style="info" %}
在AD环境中，**客户端通过与企业CA交互来请求证书**，该证书基于证书模板中定义的设置。企业CA证书会传播到每台Windows机器上的Intermediate Certification Authorities证书存储区。
{% endhint %}

* **NTAuthCertificates** AD对象定义了启用对AD的身份验证的CA证书。该对象具有**`certificationAuthority`**的**objectClass**，对象的**`cACertificate`**属性定义了一组**受信任的CA证书**。AD加入的Windows机器将这些CA传播到每台机器上的Intermediate Certification Authorities证书存储区。**客户端**应用程序只有在**NTAuthCertificates**对象定义的**一个CA**签署了认证客户端的证书时，才能使用证书对AD进行身份验证。
* **AIA**（Authority Information Access）容器保存了中间和交叉CA的AD对象。**中间CA是根CA的“子级”**，因此该容器存在的目的是帮助**验证证书链**。与证书颁发机构容器类似，AIA容器中的每个**CA都表示为AD对象**，其中objectClass属性设置为certificationAuthority，**cACertificate**属性包含CA证书的**字节**。这些CA会传播到每台Windows机器上的Intermediate Certification Authorities证书存储中。

### 客户端证书请求流程

<figure><img src="../../.gitbook/assets/image (5) (2) (2).png" alt=""><figcaption></figcaption></figure>

这是从AD CS获取证书的过程。在高层次上，客户端首先根据上面讨论的Enrolment Services容器中的对象**找到企业CA**。

1. 然后，客户端生成**公私钥对**，
2. 将公钥与其他详细信息（如证书的主题和**证书模板名称**）一起放入**证书签名请求（CSR）**消息中。然后，客户端使用其私钥**对CSR进行签名**，并将CSR发送到企业CA服务器。
3. CA服务器检查客户端是否**可以请求证书**。如果可以，它将通过查找CSR中指定的**证书模板**AD对象来确定是否发放证书。CA将检查证书模板AD对象的**权限是否允许**验证的帐户**获取证书**。
4. 如果是这样，CA将使用证书模板定义的“蓝图”设置（例如，EKU、加密设置和发放要求）以及CSR中提供的其他信息（如果证书模板设置允许）生成证书。CA使用其私钥对证书进行签名，然后将其返回给客户端。

### 证书模板

AD CS将可用的证书模板存储为具有**objectClass**为**pKICertificateTemplate**的AD对象，位于以下容器中：

`CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`

AD证书模板对象的属性**定义了其设置，其安全描述符控制**哪些**主体可以申请**证书或**编辑**证书模板。

AD证书模板对象上的**pKIExtendedKeyUsage**属性包含在模板中启用的OID数组。这些EKU OID会影响证书的**用途**。您可以在[此处找到可能的OID列表](https://www.pkisolutions.com/object-identifiers-oid-in-pki/)。

#### 身份验证OID

* `1.3.6.1.5.5.7.3.2`：客户端身份验证
* `1.3.6.1.5.2.3.4`：PKINIT客户端身份验证（需要手动添加）
* `1.3.6.1.4.1.311.20.2.2`：智能卡登录
* `2.5.29.37.0`：任何用途
* （无EKUs）：子CA
* 我们发现可以滥用的另一个EKU OID是证书请求代理OID（`1.3.6.1.4.1.311.20.2.1`）。具有此OID的证书可用于**代表其他用户请求证书**，除非设置了特定的限制。

## 证书注册

管理员需要**创建证书**模板，然后企业CA会**“发布”**该模板，使其可供客户端注册。AD CS通过将模板的名称添加到AD对象的`certificatetemplates`字段来指定在企业CA上启用证书模板。

<figure><img src="../../.gitbook/assets/image (11) (2) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
AD CS定义了注册权限 - 哪些**主体可以请求**证书 - 使用两个安全描述符：一个在**证书模板**AD对象上，另一个在**企业CA本身**上。\
客户端需要在这两个安全描述符中被授予权限才能请求证书。
{% endhint %}

### 证书模板注册权限

* **ACE授予主体Certificate-Enrollment扩展权限**。原始ACE授予主体`RIGHT_DS_CONTROL_ACCESS45`访问权限，其中**ObjectType**设置为`0e10c968-78fb-11d2-90d4-00c04f79dc5547`。此GUID对应**Certificate-Enrollment**扩展权限。
* **ACE授予主体Certificate-AutoEnrollment扩展权限**。原始ACE授予主体`RIGHT_DS_CONTROL_ACCESS48`访问权限，其中**ObjectType**设置为`a05b8cc2-17bc-4802-a710-e7c15ab866a249`。此GUID对应**Certificate-AutoEnrollment**扩展权限。
* **ACE授予主体所有ExtendedRights**。原始ACE启用`RIGHT_DS_CONTROL_ACCESS`访问权限，其中**ObjectType**设置为`00000000-0000-0000-0000-000000000000`。此GUID对应**所有扩展权限**。
* **ACE授予主体FullControl/GenericAll**。原始ACE启用FullControl/GenericAll访问权限。

### 企业CA注册权限

配置在**企业CA**上的**安全描述符**定义了这些权限，并且可以通过右键单击CA → 属性 → 安全性在证书颁发机构MMC快照`certsrv.msc`中查看。

<figure><img src="../../.gitbook/assets/image (7) (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

这最终会在CA服务器上的注册表键**`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration<CA NAME>`**中设置Security注册表值。我们遇到过几个AD CS服务器，通过远程注册表将低权限用户授予对此键的远程访问权限：

<figure><img src="../../.gitbook/assets/image (6) (2) (1).png" alt=""><figcaption></figcaption></figure>

低权限用户还可以使用`ICertAdminD2` COM接口的`GetCASecurity`方法通过DCOM枚举此项。但是，普通Windows客户端需要安装远程服务器管理工具（RSAT）才能使用它，因为COM接口及其实现它的任何COM对象在Windows上默认情况下不存在。
### 颁发要求

可能会有其他要求来控制谁可以获得证书。

#### 经理批准

**CA证书经理批准**会导致证书模板在AD对象的`msPKI-EnrollmentFlag`属性上设置`CT_FLAG_PEND_ALL_REQUESTS`（0x2）位。这将使基于该模板的所有**证书请求**进入**待定状态**（在`certsrv.msc`的“待定请求”部分可见），需要证书经理在颁发证书之前**批准或拒绝**请求：

<figure><img src="../../.gitbook/assets/image (13) (2).png" alt=""><figcaption></figcaption></figure>

#### 登记代理、授权签名和应用策略

**授权签名的数量**和**应用策略**。前者控制CA接受CSR所需的**签名数量**。后者定义了CSR签名证书必须具有的**EKU OID**。

这些设置的常见用途是用于**登记代理**。登记代理是AD CS术语，用于指可以代表其他用户**请求证书**的实体。为此，CA必须向登记代理帐户颁发一个包含至少**证书请求代理EKU**（OID 1.3.6.1.4.1.311.20.2.1）的证书。一旦颁发，登记代理就可以**代表其他用户签署CSR并请求证书**。CA将仅在以下非全面条件下（主要在默认策略模块`certpdef.dll`中实现）**将证书**作为**另一个用户**颁发给登记代理：

* Windows用户通过身份验证访问CA具有目标证书模板的登记权限。
* 如果证书模板的模式版本为1，则CA在颁发证书之前要求签名证书具有证书请求代理OID。模板的模式版本是指其AD对象的msPKI-Template-Schema-Version属性中指定的版本。
* 如果证书模板的模式版本为2：
* 模板必须设置“授权签名的数量”设置，并且必须有指定数量的登记代理签署CSR（模板的mspkira-signature AD属性定义了此设置）。换句话说，此设置指定在CA甚至考虑颁发证书之前必须有多少个登记代理签署CSR。
* 模板的“应用策略”颁发限制必须设置为“证书请求代理”。

### 请求证书

1. 使用Windows的**客户端证书登记协议**（MS-WCCE），这是一组与各种AD CS功能（包括登记）交互的分布式组件对象模型（DCOM）接口。**DCOM服务器默认启用在所有AD CS服务器上**，这是我们看到客户端请求证书的最常见方法。
2. 通过**ICertPassage远程协议**（MS-ICPR），这是一种可以通过命名管道或TCP/IP运行的**远程过程调用**（RPC）协议。
3. 访问**证书登记Web界面**。要使用此功能，ADCS服务器需要安装**证书颁发机构Web登记角色**。启用后，用户可以导航到运行在`http:///certsrv/`的托管在IIS上的ASP Web登记应用程序。
* `certipy req -ca 'corp-DC-CA' -username john@corp.local -password Passw0rd -web -debug`
4. 与**证书登记服务**（CES）交互。要使用此功能，服务器需要安装**证书登记Web服务角色**。启用后，用户可以访问Web服务`https:///_CES_Kerberos/service.svc`来请求证书。该服务与证书登记策略（通过安装证书登记策略Web服务角色安装）一起工作，客户端使用该服务在URL`https:///ADPolicyProvider_CEP_Kerberos/service.svc`上**列出证书模板**。在底层，证书登记和策略Web服务分别实现了MS-WSTEP和MS-XCEP（两个基于SOAP的协议）。
5. 使用**网络设备登记服务**。要使用此功能，服务器需要安装**网络设备登记服务角色**，允许客户端（即网络设备）通过**简单证书登记协议**（SCEP）获取证书。启用后，管理员可以从URL`http:///CertSrv/mscep_admin/`获取一次性密码（OTP）。然后管理员可以将OTP提供给网络设备，设备将使用SCEP使用URL`http://NDESSERVER/CertSrv/mscep/`请求证书。

在Windows机器上，用户可以通过启动`certmgr.msc`（用于用户证书）或`certlm.msc`（用于计算机证书），展开个人证书存储→右键单击证书→所有任务→请求新证书来请求证书。

还可以使用内置的**`certreq.exe`**命令或PowerShell的**`Get-Certificate`**命令进行证书登记。

## 证书认证

AD默认支持两种协议的证书认证：**Kerberos**和**安全通道**（Schannel）。

### Kerberos认证和NTAuthCertificates容器

简而言之，用户将使用其证书的**私钥**对**TGT请求的认证器进行签名**，然后将此请求提交给**域控制器**。域控制器执行一系列**验证步骤**，如果一切**通过**，则颁发TGT。

或者，更详细地说：

> KDC验证用户的证书（时间、路径和吊销状态），以确保证书来自受信任的源。KDC使用CryptoAPI从用户的证书到位于域控制器上的根证书颁发机构（CA）证书的**根存储**中构建**认证路径**。然后，KDC使用CryptoAPI验证预身份验证数据字段中包含的已签名认证器上的数字签名。域控制器验证签名，并使用用户证书的公钥证明请求是由与公钥对应的私钥的所有者发起的。**KDC还验证发行者是否受信任，并出现在NTAUTH证书存储中。**

这里提到的“NTAUTH证书存储”是指AD CS在以下位置安装的AD对象：

`CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`

> 通过将CA证书发布到企业NTAuth存储，管理员表示**信任CA**颁发此类证书。Windows CA会自动将其CA证书发布到此存储。

这意味着当**AD CS创建新的CA**（或更新CA证书）时，它会通过将新证书添加到对象的`cacertificate`属性来将新证书发布到**`NTAuthCertificates`**对象中：

<figure><img src="../../.gitbook/assets/image (9) (2).png" alt=""><figcaption></figcaption></figure>

在证书认证期间，域控制器可以验证认证证书是否链接到由**`NTAuthCertificates`**对象定义的CA证书。**`NTAuthCertificates`**对象中的CA证书必须再链接到根CA。这里的重点是**`NTAuthCertificates`**对象是Active Directory中证书认证的信任根！
### 安全通道（Schannel）身份验证

Schannel是Windows在建立TLS/SSL连接时使用的安全支持提供程序（SSP）。Schannel支持**客户端身份验证**（以及许多其他功能），使远程服务器能够**验证连接用户的身份**。它使用PKI实现这一点，其中证书是主要凭据。\
在**TLS握手**期间，服务器**请求客户端的证书**进行身份验证。客户端之前从服务器信任的CA颁发机构获得了客户端身份验证证书，将其证书发送给服务器。服务器然后验证证书是否正确，并在一切正常的情况下授予用户访问权限。

<figure><img src="../../.gitbook/assets/image (8) (2) (1).png" alt=""><figcaption></figcaption></figure>

当帐户使用证书对AD进行身份验证时，DC需要以某种方式将证书凭据映射到AD帐户。**Schannel**首先尝试使用Kerberos的**S4U2Self**功能将**凭据**映射到**用户**帐户。\
如果这是**不成功的**，它将尝试使用证书的**SAN扩展**，**主题**和**颁发者**字段的组合，或仅从颁发者映射**证书到用户**帐户。默认情况下，AD环境中的许多协议不支持通过Schannel进行AD身份验证。WinRM、RDP和IIS都支持使用Schannel进行客户端身份验证，但需要进行**额外的配置**，并且在某些情况下（如WinRM）无法与Active Directory集成。\
一个通常可以工作的协议（假设已经设置了AD CS）是**LDAPS**。命令`Get-LdapCurrentUser`演示了如何使用.NET库对LDAP进行身份验证。该命令执行LDAP的“Who am I？”扩展操作以显示当前正在进行身份验证的用户：

<figure><img src="../../.gitbook/assets/image (2) (4).png" alt=""><figcaption></figcaption></figure>

## AD CS枚举

与大多数AD一样，到目前为止所涵盖的所有信息都可以通过查询LDAP作为域认证但否则没有特权的用户来获取。

如果我们想**枚举企业CA**及其设置，可以在`CN=Configuration,DC=<domain>,DC=<com>`搜索基础上使用`(objectCategory=pKIEnrollmentService)` LDAP过滤器查询LDAP（此搜索基础对应于AD林的配置命名上下文）。结果将标识CA服务器的DNS主机名、CA名称本身、证书的开始和结束日期、各种标志、已发布的证书模板等。

**用于枚举易受攻击证书的工具：**

* [**Certify**](https://github.com/GhostPack/Certify)是一个C#工具，可以**枚举AD CS环境的有用配置和基础设施信息**，并可以以多种不同的方式请求证书。
* [**Certipy**](https://github.com/ly4k/Certipy)是一个**Python**工具，可以从任何系统（具有对DC的访问权限）**枚举和滥用**Active Directory证书服务（AD CS），并能够为BloodHound生成输出，由[**Lyak**](https://twitter.com/ly4k\_)（好人更好的黑客）创建。
```bash
# https://github.com/GhostPack/Certify
Certify.exe cas #enumerate trusted root CA certificates, certificates defined by the NTAuthCertificates object, and various information about Enterprise CAs
Certify.exe find #enumerate certificate templates
Certify.exe find /vulnerable #Enumerate vulenrable certificate templater

# https://github.com/ly4k/Certipy
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
certipy find -vulnerable [-hide-admins] -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128 #Search vulnerable templates

certutil.exe -TCAInfo #enumerate Enterprise CAs
certutil -v -dstemplate #enumerate certificate templates
```
## 参考资料

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者想要**获取最新版本的 PEASS 或下载 PDF 格式的 HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 NFT 收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
