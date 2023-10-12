# macOS IOKit

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Are you working in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? Or do you want to have access to the **latest version of PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our exclusive collection of [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS and HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the [**telegram group**](https://t.me/peass) or **follow me** on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Share your hacking tricks by sending PR to** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## 基本信息

I/O Kit是XNU内核中的开源、面向对象的**设备驱动程序框架**，负责添加和管理**动态加载的设备驱动程序**。这些驱动程序允许将模块化代码动态添加到内核中，以便与不同的硬件一起使用。

IOKit驱动程序基本上是从内核中**导出函数**。这些函数的参数**类型**是**预定义**的并且经过验证。此外，与XPC类似，IOKit只是在**Mach消息**之上的另一层。

**IOKit XNU内核代码**由Apple在[https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit)上开源。此外，用户空间的IOKit组件也是开源的[https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser)。

然而，**没有IOKit驱动程序**是开源的。不过，偶尔会发布带有符号的驱动程序版本，这样更容易进行调试。查看如何[**从固件中获取驱动程序扩展**](./#ipsw)**。**

它是用**C++**编写的。您可以使用以下命令获取解析后的C++符号：
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit暴露的函数在客户端尝试调用函数时可以执行额外的安全检查，但请注意应用程序通常受到沙箱的限制，只能与IOKit函数进行交互。
{% endhint %}

## 驱动程序

在macOS中，它们位于：

* **`/System/Library/Extensions`**
* 内置于OS X操作系统中的KEXT文件。
* **`/Library/Extensions`**
* 第三方软件安装的KEXT文件。

在iOS中，它们位于：

* **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
直到第9个，列出的驱动程序**在地址0处加载**。这意味着它们不是真正的驱动程序，而是**内核的一部分，无法卸载**。

要查找特定的扩展，可以使用：
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
要加载和卸载内核扩展，请执行以下操作：
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry**是macOS和iOS中IOKit框架的关键部分，它作为一个数据库用于表示系统的硬件配置和状态。它是一个**层次化的对象集合，表示系统上加载的所有硬件和驱动程序，以及它们之间的关系**。

您可以使用命令行工具**`ioreg`**从控制台检查IORegistry（对iOS特别有用）。
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
你可以从[https://developer.apple.com/download/all/](https://developer.apple.com/download/all/)下载**Xcode附加工具**中的**IORegistryExplorer**，并通过**图形界面**检查**macOS IORegistry**。

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

在IORegistryExplorer中，"planes"用于组织和显示IORegistry中不同对象之间的关系。每个plane表示一种特定类型的关系或系统硬件和驱动程序配置的特定视图。以下是您可能在IORegistryExplorer中遇到的一些常见plane：

1. **IOService Plane**：这是最常见的plane，显示表示驱动程序和nub（驱动程序之间的通信通道）的服务对象。它显示这些对象之间的提供者-客户端关系。
2. **IODeviceTree Plane**：该plane表示设备连接到系统时的物理连接。通常用于可视化通过USB或PCI等总线连接的设备的层次结构。
3. **IOPower Plane**：以电源管理方面的对象及其关系显示。它可以显示哪些对象影响其他对象的电源状态，对于调试与电源相关的问题非常有用。
4. **IOUSB Plane**：专注于USB设备及其关系，显示USB集线器和连接设备的层次结构。
5. **IOAudio Plane**：该plane用于表示系统中的音频设备及其关系。
6. ...

## 驱动程序通信代码示例

以下代码连接到IOKit服务`"YourServiceNameHere"`，并调用选择器0中的函数。为此：

* 首先调用**`IOServiceMatching`**和**`IOServiceGetMatchingServices`**获取服务。
* 然后调用**`IOServiceOpen`**建立连接。
* 最后使用**`IOConnectCallScalarMethod`**调用函数，指示选择器0（选择器是您要调用的函数分配的编号）。
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
有**其他**函数可以用来调用IOKit函数，除了**`IOConnectCallScalarMethod`**，还有**`IOConnectCallMethod`**，**`IOConnectCallStructMethod`**...

## 反向驱动程序入口点

例如，您可以从[**固件映像（ipsw）**](./#ipsw)中获取这些函数。然后，将其加载到您喜欢的反编译器中。

您可以从**`externalMethod`**函数开始反编译，因为这是将接收调用并调用正确函数的驱动程序函数：

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

那个可怕的调用解码的意思是：
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

请注意，在上面的定义中，缺少了**`self`**参数，正确的定义应该是：

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

实际上，您可以在[https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388)找到真正的定义：
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
使用这些信息，您可以重写Ctrl+Right -> `Edit function signature`并设置已知类型：

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

新的反编译代码如下所示：

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

下一步，我们需要定义**`IOExternalMethodDispatch2022`**结构体。它在[https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176)中是开源的，您可以定义它：

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

现在，根据`(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`，您可以看到很多数据：

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

将数据类型更改为**`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

更改后：

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

现在我们知道这里有一个**由7个元素组成的数组**（检查最终的反编译代码），点击创建一个由7个元素组成的数组：

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

创建数组后，您可以看到所有导出的函数：

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
如果您记得，要从用户空间**调用**一个**导出的**函数，我们不需要调用函数的名称，而是**选择器编号**。在这里，您可以看到选择器**0**是函数**`initializeDecoder`**，选择器**1**是**`startDecoder`**，选择器**2**是**`initializeEncoder`**...
{% endhint %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
