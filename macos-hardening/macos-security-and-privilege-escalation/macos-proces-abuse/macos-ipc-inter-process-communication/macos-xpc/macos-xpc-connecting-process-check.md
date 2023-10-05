# macOS XPC 连接进程检查

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告**吗？或者你想要访问 **PEASS 的最新版本或下载 HackTricks 的 PDF** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## XPC 连接进程检查

当与 XPC 服务建立连接时，服务器将检查连接是否被允许。通常会执行以下检查：

1. 检查连接的 **进程是否使用 Apple 签名的** 证书（仅由 Apple 颁发）。
* 如果未经验证，攻击者可以创建一个 **伪造的证书** 来匹配其他任何检查。
2. 检查连接的进程是否使用 **组织的证书** 进行签名（团队 ID 验证）。
* 如果未经验证，可以使用 Apple 的 **任何开发者证书** 进行签名并连接到服务。
3. 检查连接的进程是否包含一个 **正确的 Bundle ID**。
* 如果未经验证，可以使用由同一组织签名的任何工具与 XPC 服务进行交互。
4. （4 或 5）检查连接的进程是否具有 **正确的软件版本号**。
* 如果未经验证，即使其他检查已经通过，也可以使用旧的、存在安全漏洞的客户端进行连接到 XPC 服务的过程注入。
5. （4 或 5）检查连接的进程是否具有带有危险权限的强化运行时（例如允许加载任意库或使用 DYLD 环境变量的权限）。
* 如果未经验证，客户端可能容易受到代码注入的攻击。
6. 检查连接的进程是否具有允许其连接到服务的 **entitlement**。这适用于 Apple 二进制文件。
7. **验证** 必须基于连接的 **客户端的审计令牌** 而不是其进程 ID（PID），因为前者可以防止 PID 重用攻击。
* 开发人员很少使用审计令牌 API 调用，因为它是 **私有的**，所以 Apple 可能随时 **更改**。此外，Mac App Store 应用程序不允许使用私有 API。

有关 PID 重用攻击检查的更多信息，请参阅：

{% content-ref url="../../../mac-os-architecture/macos-ipc-inter-process-communication/macos-pid-reuse.md" %}
[macos-pid-reuse.md](../../../mac-os-architecture/macos-ipc-inter-process-communication/macos-pid-reuse.md)
{% endcontent-ref %}

### Trustcache - 防止降级攻击

Trustcache 是一种在 Apple Silicon 机器上引入的防御方法，它存储了 Apple 二进制文件的 CDHSAH 数据库，因此只有允许的非修改二进制文件才能执行。这可以防止执行降级版本。

### 代码示例

服务器将在一个名为 **`shouldAcceptNewConnection`** 的函数中实现此 **验证**。

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

对象NSXPCConnection有一个**私有**属性**`auditToken`**（应该使用但可能会更改）和一个**公共**属性**`processIdentifier`**（不应该使用）。

可以使用以下方式验证连接的进程：

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
如果开发者不想检查客户端的版本，他至少可以检查客户端是否容易受到进程注入的攻击：

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

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
