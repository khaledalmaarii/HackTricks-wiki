# macOS XPC 连接进程检查

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

## XPC 连接进程检查

当与 XPC 服务建立连接时，服务器将检查该连接是否被允许。通常会执行以下检查：

1. 检查连接的 **进程是否使用 Apple 签名** 的证书（仅由 Apple 发放）。
* 如果 **未验证**，攻击者可以创建一个 **伪造证书** 来匹配其他检查。
2. 检查连接进程是否使用 **组织的证书**（团队 ID 验证）。
* 如果 **未验证**，可以使用 **任何开发者证书** 从 Apple 进行签名，并连接到服务。
3. 检查连接进程 **是否包含正确的包 ID**。
* 如果 **未验证**，任何 **由同一组织签名的工具** 都可以用来与 XPC 服务交互。
4. (4 或 5) 检查连接进程是否具有 **正确的软件版本号**。
* 如果 **未验证**，旧的、不安全的客户端，易受进程注入攻击，可以连接到 XPC 服务，即使其他检查已到位。
5. (4 或 5) 检查连接进程是否具有没有危险权限的 **强化运行时**（如允许加载任意库或使用 DYLD 环境变量的权限）。
* 如果 **未验证**，客户端可能 **易受代码注入**。
6. 检查连接进程是否具有允许其连接到服务的 **权限**。这适用于 Apple 二进制文件。
7. **验证** 必须 **基于** 连接 **客户端的审计令牌** **而不是** 其进程 ID (**PID**)，因为前者可以防止 **PID 重用攻击**。
* 开发者 **很少使用审计令牌** API 调用，因为它是 **私有的**，所以 Apple 可能会 **随时更改**。此外，Mac App Store 应用不允许使用私有 API。
* 如果使用 **`processIdentifier`** 方法，可能会存在漏洞。
* 应使用 **`xpc_dictionary_get_audit_token`** 而不是 **`xpc_connection_get_audit_token`**，因为后者在某些情况下也可能 [存在漏洞](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。

### 通信攻击

有关 PID 重用攻击的更多信息，请查看：

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

有关 **`xpc_connection_get_audit_token`** 攻击的更多信息，请查看：

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - 降级攻击防范

Trustcache 是一种防御方法，旨在 Apple Silicon 机器中引入，存储 Apple 二进制文件的 CDHSAH 数据库，以便仅允许未修改的二进制文件执行。这可以防止降级版本的执行。

### 代码示例

服务器将在名为 **`shouldAcceptNewConnection`** 的函数中实现此 **验证**。

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

对象 NSXPCConnection 有一个 **私有** 属性 **`auditToken`**（应该使用但可能会改变）和一个 **公共** 属性 **`processIdentifier`**（不应该使用）。

连接的进程可以通过以下方式进行验证：

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
{% endcode %}

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
