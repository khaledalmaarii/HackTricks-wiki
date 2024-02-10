# macOS IOKit

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하고 계신가요? **회사를 HackTricks에서 홍보**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 플랜**](https://github.com/sponsors/carlospolop)을 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. [**NFT**](https://opensea.io/collection/the-peass-family)의 독점 컬렉션입니다.
* [**PEASS와 HackTricks의 공식 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) **Discord 그룹** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 팔로우하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* [**hacktricks repo**](https://github.com/carlospolop/hacktricks)와 [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 **PR을 보내어 해킹 팁을 공유**하세요.

</details>

## 기본 정보

I/O Kit은 XNU 커널에서 사용되는 오픈 소스, 객체 지향 **디바이스 드라이버 프레임워크**로, **동적으로 로드되는 디바이스 드라이버**를 처리합니다. 이를 통해 다양한 하드웨어를 지원하기 위해 커널에 모듈식 코드를 실시간으로 추가할 수 있습니다.

IOKit 드라이버는 기본적으로 커널에서 **함수를 내보냅니다**. 이러한 함수의 매개변수 **유형**은 **미리 정의**되어 있으며 확인됩니다. 또한, XPC와 마찬가지로 IOKit은 Mach 메시지 위에 있는 **또 다른 레이어**입니다.

**IOKit XNU 커널 코드**는 Apple에서 [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit)에서 오픈 소스로 제공됩니다. 또한, 사용자 공간 IOKit 구성 요소도 오픈 소스로 제공됩니다. [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

그러나 **IOKit 드라이버**는 오픈 소스가 아닙니다. 그래도 때때로 드라이버의 릴리스에는 디버깅을 더 쉽게 만드는 기호가 포함될 수 있습니다. [**여기에서 펌웨어에서 드라이버 확장을 가져오는 방법을 확인하세요**](./#ipsw)**.**

이는 **C++**로 작성되었습니다. 다음 명령을 사용하여 C++ 심볼을 디맹글링할 수 있습니다:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit 노출된 함수는 클라이언트가 함수를 호출하려고 할 때 추가적인 보안 검사를 수행할 수 있지만, 앱은 일반적으로 IOKit 함수와 상호 작용할 수 있는 샌드박스에 제한됩니다.
{% endhint %}

## 드라이버

macOS에서는 다음 위치에 있습니다:

* **`/System/Library/Extensions`**
* OS X 운영 체제에 내장된 KEXT 파일입니다.
* **`/Library/Extensions`**
* 제3자 소프트웨어에 의해 설치된 KEXT 파일입니다.

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
9까지의 번호로 나열된 드라이버들은 **주소 0에 로드**됩니다. 이는 실제 드라이버가 아니라 **커널의 일부이며 언로드할 수 없습니다**.

특정 확장자를 찾으려면 다음을 사용할 수 있습니다:
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

**IORegistry**는 macOS와 iOS의 IOKit 프레임워크의 중요한 부분으로, 시스템의 하드웨어 구성과 상태를 나타내는 데이터베이스 역할을 합니다. 이는 시스템에 로드된 하드웨어와 드라이버를 나타내는 **계층적인 객체의 컬렉션**이며, 이들의 관계를 나타냅니다.

**`ioreg`** 명령어를 사용하여 IORegistry를 검사할 수 있으며, 특히 iOS에서 유용하게 사용됩니다.
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**`IORegistryExplorer`**를 [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/)에서 **Xcode 추가 도구**를 통해 다운로드할 수 있으며, **그래픽** 인터페이스를 통해 **macOS IORegistry**를 검사할 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer에서 "planes"은 IORegistry의 다른 객체 간의 관계를 조직화하고 표시하는 데 사용됩니다. 각 plane은 특정 유형의 관계 또는 시스템의 하드웨어 및 드라이버 구성의 특정 뷰를 나타냅니다. IORegistryExplorer에서 만날 수 있는 일부 일반적인 plane은 다음과 같습니다:

1. **IOService Plane**: 가장 일반적인 plane으로, 드라이버와 nub(드라이버 간의 통신 채널)를 나타내는 서비스 객체를 표시합니다. 이는 이러한 객체 간의 공급자-클라이언트 관계를 보여줍니다.
2. **IODeviceTree Plane**: 이 plane은 시스템에 연결된 장치들의 물리적 연결을 나타냅니다. USB 또는 PCI와 같은 버스를 통해 연결된 장치의 계층 구조를 시각화하는 데 자주 사용됩니다.
3. **IOPower Plane**: 전원 관리 관점에서 객체와 그들의 관계를 표시합니다. 다른 객체의 전원 상태에 영향을 주는 객체를 보여줄 수 있으며, 전원 관련 문제를 디버깅하는 데 유용합니다.
4. **IOUSB Plane**: 특히 USB 장치와 그들의 관계에 초점을 맞춘 plane으로, USB 허브와 연결된 장치의 계층 구조를 보여줍니다.
5. **IOAudio Plane**: 이 plane은 시스템 내의 오디오 장치와 그들의 관계를 나타내는 데 사용됩니다.
6. ...

## 드라이버 통신 코드 예제

다음 코드는 IOKit 서비스 `"YourServiceNameHere"`에 연결하고 선택기 0 내의 함수를 호출합니다. 이를 위해:

* 먼저 **`IOServiceMatching`**과 **`IOServiceGetMatchingServices`**를 호출하여 서비스를 가져옵니다.
* 그런 다음 **`IOServiceOpen`**을 호출하여 연결을 설정합니다.
* 마지막으로 **`IOConnectCallScalarMethod`**를 사용하여 선택기 0(함수에 할당된 번호)를 지정하여 함수를 호출합니다.
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
**다른** 함수들도 있습니다. **`IOConnectCallScalarMethod`** 외에도 **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`** 등을 사용하여 IOKit 함수를 호출할 수 있습니다...

## 드라이버 엔트리포인트 역어셈블링

예를 들어 [**펌웨어 이미지 (ipsw)**](./#ipsw)에서 이를 얻을 수 있습니다. 그런 다음, 좋아하는 디컴파일러에 로드하십시오.

호출을 받고 올바른 함수를 호출하는 드라이버 함수인 **`externalMethod`** 함수를 디컴파일링할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

그 지저분한 호출은 다음을 의미합니다:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

이전 정의에서 **`self`** 매개변수가 누락된 것을 주목하세요. 올바른 정의는 다음과 같습니다:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

실제 정의는 [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388)에서 찾을 수 있습니다:
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
이 정보를 사용하여 Ctrl+Right -> `함수 시그니처 편집`을 다시 작성하고 알려진 유형을 설정할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

새로운 디컴파일된 코드는 다음과 같이 보일 것입니다:

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

다음 단계에서는 **`IOExternalMethodDispatch2022`** 구조체를 정의해야 합니다. [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176)에서 오픈 소스로 제공되고 있으므로 다음과 같이 정의할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

이제 `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`를 따라가면 많은 데이터를 볼 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

데이터 유형을 **`IOExternalMethodDispatch2022:`**로 변경하세요.

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

변경 후:

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

이제 여기에 **7개의 요소 배열**이 있다는 것을 알 수 있습니다 (최종 디컴파일된 코드를 확인하세요). 7개의 요소 배열을 생성하려면 클릭하세요:

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

배열이 생성된 후 내보낸 함수를 모두 볼 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
기억하시나요? 사용자 공간에서 **내보낸** 함수를 **호출**할 때 함수 이름이 아니라 **선택기 번호**를 호출해야 합니다. 여기에서 선택기 **0**은 함수 **`initializeDecoder`**이고, 선택기 **1**은 **`startDecoder`**이고, 선택기 **2**는 **`initializeEncoder`**입니다...
{% endhint %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</summary>

* **사이버 보안 회사**에서 일하고 계신가요? 귀사의 광고를 HackTricks에서 보여주거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 플랜**](https://github.com/sponsors/carlospolop)을 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. [**NFTs**](https://opensea.io/collection/the-peass-family)의 독점 컬렉션입니다.
* [**PEASS와 HackTricks의 공식 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) **Discord 그룹** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 팔로우하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* [**hacktricks repo**](https://github.com/carlospolop/hacktricks)와 [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)로 **PR을 보내서** 해킹 요령을 공유하세요.

</details>
