# macOS IOKit

<details>

<summary><strong>AWS 해킹을 처음부터 전문가까지 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## 기본 정보

I/O Kit은 XNU 커널의 오픈 소스, 객체 지향 **장치 드라이버 프레임워크**로, **동적으로 로드된 장치 드라이버**를 처리합니다. 이를 통해 모듈식 코드를 커널에 실시간으로 추가하여 다양한 하드웨어를 지원합니다.

IOKit 드라이버는 기본적으로 커널에서 **함수를 내보냅니다**. 이러한 함수 매개변수 **유형**은 **미리 정의**되어 있으며 확인됩니다. 또한, XPC와 유사하게 IOKit은 Mach 메시지 위에 있는 또 다른 레이어일 뿐입니다.

**IOKit XNU 커널 코드**는 Apple에 의해 오픈 소스로 공개되어 있으며 [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit)에서 확인할 수 있습니다. 또한, 사용자 공간 IOKit 구성 요소도 오픈 소스로 공개되어 있습니다 [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

그러나 **IOKit 드라이버**는 오픈 소스가 아닙니다. 그래도 때때로 드라이버의 릴리스가 디버깅을 쉽게 만드는 심볼을 제공할 수 있습니다. [**여기에서 펌웨어에서 드라이버 확장을 가져오는 방법을 확인하세요**](./#ipsw)**.**

이는 **C++**로 작성되었습니다. 다음과 같이 C++ 심볼을 해석할 수 있습니다:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit 노출된 함수들은 클라이언트가 함수를 호출하려고 시도할 때 추가 보안 검사를 수행할 수 있지만, 앱들은 일반적으로 IOKit 함수들과 상호 작용할 수 있는 샌드박스에 의해 제한됩니다.
{% endhint %}

## 드라이버

macOS에서는 다음 위치에 있습니다:

- **`/System/Library/Extensions`**
- OS X 운영 체제에 내장된 KEXT 파일들.
- **`/Library/Extensions`**
- 제3자 소프트웨어에 의해 설치된 KEXT 파일들

iOS에서는 다음 위치에 있습니다:

- **`/System/Library/Extensions`**
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
숫자 9까지 나열된 드라이버들은 **주소 0에 로드됩니다**. 이는 실제 드라이버가 아닌 **커널의 일부이며 언로드할 수 없습니다**.

특정 확장자를 찾으려면 다음을 사용할 수 있습니다:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
커널 확장 프로그램을 로드하고 언로드하려면 다음을 수행하십시오:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry(입출력 레지스트리)**는 macOS와 iOS의 IOKit 프레임워크의 중요한 부분으로, 시스템의 하드웨어 구성 및 상태를 나타내는 데이터베이스 역할을 합니다. 이는 시스템에 로드된 모든 하드웨어 및 드라이버를 나타내는 **객체들의 계층적인 컬렉션**이며, 서로의 관계를 보여줍니다.

**`ioreg`** 명령어를 사용하여 CLI에서 IORegistry를 가져와 검사할 수 있습니다(특히 iOS에서 유용).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**`IORegistryExplorer`**을 [**Xcode 추가 도구**](https://developer.apple.com/download/all/)에서 다운로드할 수 있으며, **그래픽** 인터페이스를 통해 **macOS IORegistry**를 검사할 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer에서 "planes"는 IORegistry의 다른 객체 간의 관계를 조직화하고 표시하는 데 사용됩니다. 각 plane은 시스템 하드웨어 및 드라이버 구성의 특정 보기나 특정 유형의 관계를 나타냅니다. 다음은 IORegistryExplorer에서 만날 수 있는 일반적인 plane 중 일부입니다:

1. **IOService Plane**: 이것은 가장 일반적인 plane으로, 드라이버와 nub(드라이버 간의 통신 채널)를 나타내는 서비스 객체를 표시합니다. 이 객체들 간의 제공자-클라이언트 관계를 보여줍니다.
2. **IODeviceTree Plane**: 이 plane은 시스템에 연결된 장치들 간의 물리적 연결을 나타냅니다. USB 또는 PCI와 같은 버스를 통해 연결된 장치들의 계층 구조를 시각화하는 데 자주 사용됩니다.
3. **IOPower Plane**: 전원 관리 관점에서 객체와 그 관계를 표시합니다. 다른 객체들의 전원 상태에 영향을 주는 객체를 보여주어 전원 관련 문제의 디버깅에 유용합니다.
4. **IOUSB Plane**: USB 장치 및 그 관계에 특히 초점을 맞춘 것으로, USB 허브 및 연결된 장치의 계층 구조를 보여줍니다.
5. **IOAudio Plane**: 이 plane은 시스템 내의 오디오 장치와 그 관계를 나타내는 데 사용됩니다.
6. ...

## 드라이버 통신 코드 예시

다음 코드는 IOKit 서비스 `"YourServiceNameHere"`에 연결하고 셀렉터 0 내부의 함수를 호출합니다. 이를 위해:

* 먼저 **`IOServiceMatching`** 및 **`IOServiceGetMatchingServices`**를 호출하여 서비스를 가져옵니다.
* 그런 다음 **`IOServiceOpen`**을 호출하여 연결을 설정합니다.
* 마지막으로 **`IOConnectCallScalarMethod`**를 사용하여 셀렉터 0(호출하려는 함수에 할당된 번호)를 지정하여 함수를 호출합니다.
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
**`IOConnectCallScalarMethod`**와 같은 **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**과 같은 IOKit 함수를 호출하는 데 사용할 수 있는 **다른** 함수들이 있습니다.

## 드라이버 엔트리포인트 역어셈블링

예를 들어 [**펌웨어 이미지 (ipsw)**](./#ipsw)에서 이러한 함수들을 얻을 수 있습니다. 그런 다음, 즐겨 사용하는 디컴파일러에 로드하십시오.

올바른 함수를 호출하는 호출을 받는 드라이버 함수인 **`externalMethod`** 함수의 디컴파일을 시작할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

그 지저분한 호출을 해석하면:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

이전 정의에서 **`self`** 매개변수가 누락된 것을 주목하세요. 올바른 정의는 다음과 같을 것입니다:

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
이 정보를 사용하여 Ctrl+Right -> `함수 서명 편집`을 다시 작성하고 알려진 유형을 설정할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

새로 디컴파일된 코드는 다음과 같이 보일 것입니다:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

다음 단계로 진행하려면 **`IOExternalMethodDispatch2022`** 구조체를 정의해야 합니다. 이는 [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176)에서 오픈소스로 제공되며, 다음과 같이 정의할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

이제 `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`를 따라가면 많은 데이터를 볼 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

데이터 유형을 **`IOExternalMethodDispatch2022:`**로 변경하세요:

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

변경 후:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

이제 여기에 **7개 요소의 배열**이 있는 것을 알 수 있습니다 (최종 디컴파일된 코드를 확인하세요). 7개 요소의 배열을 생성하려면 클릭하세요:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

배열이 생성된 후 모든 내보낸 함수를 볼 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
기억하시나요? 사용자 공간에서 **내보낸** 함수를 **호출**할 때 함수 이름을 호출할 필요가 없고 **선택기 번호**를 호출해야 합니다. 여기서 선택기 **0**은 함수 **`initializeDecoder`**를 나타내고, 선택기 **1**은 **`startDecoder`**를 나타내며, 선택기 **2**는 **`initializeEncoder`**를 나타냅니다...
{% endhint %}
