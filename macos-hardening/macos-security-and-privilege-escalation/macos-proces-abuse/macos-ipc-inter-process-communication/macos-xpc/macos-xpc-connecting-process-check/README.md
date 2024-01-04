# macOS XPC 连接进程检查

<details>

<summary><strong>从零到英雄学习 AWS 黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## XPC 连接进程检查

当与 XPC 服务建立连接时，服务器将检查是否允许连接。通常会执行以下检查：

1. 检查连接的**进程是否由苹果签名**的证书签名（只由苹果发放）。
   * 如果这个**未经验证**，攻击者可以创建一个**假证书**来匹配任何其他检查。
2. 检查连接的进程是否由**组织的证书**签名（团队 ID 验证）。
   * 如果这个**未经验证**，**任何苹果的开发者证书**都可以用来签名，并连接到服务。
3. 检查连接的进程**是否包含正确的捆绑 ID**。
   * 如果这个**未经验证**，任何**由同一组织签名**的工具都可以用来与 XPC 服务交互。
4. (4 或 5) 检查连接的进程是否有一个**正确的软件版本号**。
   * 如果这个**未经验证**，旧的、不安全的客户端，容易受到进程注入攻击的客户端，即使其他检查到位，也可以用来连接到 XPC 服务。
5. (4 或 5) 检查连接的进程是否启用了硬化运行时，没有危险的权限（比如允许加载任意库或使用 DYLD 环境变量的权限）
   * 如果这个**未经验证**，客户端可能**容易受到代码注入攻击**
6. 检查连接的进程是否有一个**权限**，允许它连接到服务。这适用于苹果的二进制文件。
7. **验证**必须**基于**连接**客户端的审计令牌**，**而不是**它的进程 ID (**PID**)，因为前者可以防止**PID 重用攻击**。
   * 开发者**很少使用审计令牌** API 调用，因为它是**私有的**，所以苹果可以随时**更改**。此外，Mac App Store 应用不允许使用私有 API。
   * 如果使用了方法 **`processIdentifier`**，它可能会受到攻击
   * 应该使用 **`xpc_dictionary_get_audit_token`** 而不是 **`xpc_connection_get_audit_token`**，因为后者在某些情况下也可能[受到攻击](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。

### 通信攻击

有关 PID 重用攻击的更多信息，请查看：

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

有关 **`xpc_connection_get_audit_token`** 攻击的更多信息，请查看：

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - 防止降级攻击

Trustcache 是在苹果硅芯片机器中引入的一种防御方法，它存储了苹果二进制文件的 CDHSAH 数据库，因此只允许执行未修改的允许的二进制文件。这可以防止执行降级版本。

### 代码示例

服务器将在一个名为 **`shouldAcceptNewConnection`** 的函数中实现这个**验证**。

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

对象 NSXPCConnection 有一个**私有**属性 **`auditToken`**（应该使用的，但可能会变化）和一个**公共**属性 **`processIdentifier`**（不应该使用的）。

连接进程可以通过类似以下方式进行验证：

{% code overflow="wrap" %}
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
{% endcode %}

如果开发者不想检查客户端的版本，他至少可以检查客户端是否不易受到进程注入的攻击：

{% code overflow="wrap" %}
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
<details>

<summary><strong>从零开始学习AWS黑客攻击直至成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
