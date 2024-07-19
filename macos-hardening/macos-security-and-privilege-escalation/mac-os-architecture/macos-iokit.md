# macOS IOKit

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

I/O Kit은 XNU 커널의 오픈 소스 객체 지향 **장치 드라이버 프레임워크**로, **동적으로 로드된 장치 드라이버**를 처리합니다. 이는 다양한 하드웨어를 지원하며, 커널에 모듈식 코드를 즉시 추가할 수 있게 해줍니다.

IOKit 드라이버는 기본적으로 **커널에서 함수를 내보냅니다**. 이 함수 매개변수 **유형**은 **미리 정의되어** 있으며 검증됩니다. 또한, XPC와 유사하게, IOKit은 **Mach 메시지** 위에 또 다른 레이어입니다.

**IOKit XNU 커널 코드**는 Apple에 의해 [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit)에서 오픈 소스화되었습니다. 또한, 사용자 공간 IOKit 구성 요소도 오픈 소스입니다 [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

그러나 **IOKit 드라이버**는 오픈 소스가 아닙니다. 어쨌든, 때때로 드라이버의 릴리스가 디버깅을 쉽게 해주는 기호와 함께 제공될 수 있습니다. [**펌웨어에서 드라이버 확장을 가져오는 방법을 확인하세요**](./#ipsw)**.**

C++로 작성되었습니다. 다음을 사용하여 디맹글된 C++ 기호를 얻을 수 있습니다:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **노출된 함수**는 클라이언트가 함수를 호출하려고 할 때 **추가 보안 검사를** 수행할 수 있지만, 앱은 일반적으로 IOKit 함수와 상호작용할 수 있는 **샌드박스**에 의해 **제한**된다는 점에 유의해야 합니다.
{% endhint %}

## 드라이버

macOS에서는 다음 위치에 있습니다:

* **`/System/Library/Extensions`**
* OS X 운영 체제에 내장된 KEXT 파일.
* **`/Library/Extensions`**
* 3rd 파티 소프트웨어에 의해 설치된 KEXT 파일

iOS에서는 다음 위치에 있습니다:

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
9번까지 나열된 드라이버는 **주소 0에 로드됩니다**. 이는 이들이 실제 드라이버가 아니라 **커널의 일부이며 언로드할 수 없음을 의미합니다**.

특정 확장을 찾기 위해 다음을 사용할 수 있습니다:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
커널 확장을 로드하고 언로드하려면 다음을 수행하십시오:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry**는 macOS 및 iOS의 IOKit 프레임워크에서 시스템의 하드웨어 구성 및 상태를 나타내는 데이터베이스의 중요한 부분입니다. 이는 **시스템에 로드된 모든 하드웨어 및 드라이버를 나타내는 객체의 계층적 컬렉션**이며, 이들 간의 관계를 나타냅니다.

콘솔에서 IORegistry를 검사하기 위해 cli **`ioreg`**를 사용하여 이를 얻을 수 있습니다(특히 iOS에 유용합니다).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
You could download **`IORegistryExplorer`** from **Xcode Additional Tools** from [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) and inspect the **macOS IORegistry** through a **graphical** interface.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer, "planes" are used to organize and display the relationships between different objects in the IORegistry. Each plane represents a specific type of relationship or a particular view of the system's hardware and driver configuration. Here are some of the common planes you might encounter in IORegistryExplorer:

1. **IOService Plane**: 가장 일반적인 평면으로, 드라이버와 넙스(드라이버 간의 통신 채널)를 나타내는 서비스 객체를 표시합니다. 이 객체들 간의 공급자-클라이언트 관계를 보여줍니다.
2. **IODeviceTree Plane**: 이 평면은 시스템에 연결된 장치 간의 물리적 연결을 나타냅니다. USB 또는 PCI와 같은 버스를 통해 연결된 장치의 계층 구조를 시각화하는 데 자주 사용됩니다.
3. **IOPower Plane**: 전원 관리 측면에서 객체와 그 관계를 표시합니다. 다른 객체의 전원 상태에 영향을 미치는 객체를 보여줄 수 있어 전원 관련 문제를 디버깅하는 데 유용합니다.
4. **IOUSB Plane**: USB 장치와 그 관계에 특별히 초점을 맞추어 USB 허브와 연결된 장치의 계층 구조를 보여줍니다.
5. **IOAudio Plane**: 이 평면은 시스템 내의 오디오 장치와 그 관계를 나타내기 위한 것입니다.
6. ...

## Driver Comm Code Example

The following code connects to the IOKit service `"YourServiceNameHere"` and calls the function inside the selector 0. For it:

* it first calls **`IOServiceMatching`** and **`IOServiceGetMatchingServices`** to get the service.
* It then establish a connection calling **`IOServiceOpen`**.
* And it finally calls a function with **`IOConnectCallScalarMethod`** indicating the selector 0 (the selector is the number the function you want to call has assigned).
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
There are **other** functions that can be used to call IOKit functions apart of **`IOConnectCallScalarMethod`** like **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## 드라이버 진입점 리버싱

예를 들어 [**펌웨어 이미지(ipsw)**](./#ipsw)에서 이를 얻을 수 있습니다. 그런 다음, 좋아하는 디컴파일러에 로드하세요.

**`externalMethod`** 함수를 디컴파일하기 시작할 수 있습니다. 이 함수는 호출을 받고 올바른 함수를 호출하는 드라이버 함수입니다:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

그 끔찍한 호출의 디맥글된 의미는: 

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

이전 정의에서 **`self`** 매개변수가 누락된 점에 유의하세요. 올바른 정의는 다음과 같습니다:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

실제로, [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388)에서 실제 정의를 찾을 수 있습니다:
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
이 정보를 사용하여 Ctrl+Right -> `Edit function signature`를 다시 작성하고 알려진 유형을 설정할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

새로 디컴파일된 코드는 다음과 같이 보일 것입니다:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

다음 단계에서는 **`IOExternalMethodDispatch2022`** 구조체를 정의해야 합니다. 이는 [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176)에서 오픈 소스로 제공되며, 이를 정의할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

이제 `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`를 따라가면 많은 데이터가 보입니다:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

데이터 유형을 **`IOExternalMethodDispatch2022:`**로 변경합니다:

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

변경 후:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

이제 여기에서 **7개의 요소로 구성된 배열**이 있다는 것을 알 수 있습니다(최종 디컴파일된 코드를 확인하세요). 7개의 요소로 구성된 배열을 생성하려면 클릭합니다:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

배열이 생성된 후에는 모든 내보낸 함수를 볼 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
기억하신다면, 사용자 공간에서 **내보낸** 함수를 **호출**하기 위해 함수의 이름을 호출할 필요는 없고, **선택자 번호**를 호출해야 합니다. 여기에서 선택자 **0**은 함수 **`initializeDecoder`**, 선택자 **1**은 **`startDecoder`**, 선택자 **2**는 **`initializeEncoder`**입니다...
{% endhint %}

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.

</details>
{% endhint %}
