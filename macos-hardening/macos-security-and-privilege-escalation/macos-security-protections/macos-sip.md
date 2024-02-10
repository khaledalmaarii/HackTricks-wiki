# macOS SIP

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## **기본 정보**

macOS의 **시스템 무결성 보호 (SIP)**는 가장 권한이 있는 사용자도 시스템의 핵심 폴더에 무단으로 변경을 가하는 것을 방지하기 위해 설계된 메커니즘입니다. 이 기능은 보호된 영역에서 파일을 추가, 수정 또는 삭제하는 것과 같은 작업을 제한하여 시스템의 무결성을 유지하는 데 중요한 역할을 합니다. SIP에 의해 보호되는 주요 폴더는 다음과 같습니다:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

SIP의 동작을 규정하는 규칙은 **`/System/Library/Sandbox/rootless.conf`**에 위치한 구성 파일에서 정의됩니다. 이 파일에서 별표 (*)로 접두사가 붙은 경로는 엄격한 SIP 제한의 예외로 표시됩니다.

다음은 예시입니다:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
이 코드 조각은 SIP가 일반적으로 **`/usr`** 디렉토리를 보호하지만, 특정 하위 디렉토리 (`/usr/libexec/cups`, `/usr/local`, `/usr/share/man`)는 경로 앞에 별표 (*)가 표시되어 수정이 허용된다는 것을 의미합니다.

SIP로 보호되는 디렉토리나 파일을 확인하려면 **`ls -lOd`** 명령을 사용하여 **`restricted`** 또는 **`sunlnk`** 플래그의 존재 여부를 확인할 수 있습니다. 예를 들어:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
이 경우, **`sunlnk`** 플래그는 `/usr/libexec/cups` 디렉토리 자체가 **삭제될 수 없음**을 나타냅니다. 그러나 그 안에 있는 파일은 생성, 수정 또는 삭제될 수 있습니다.

반면에:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
여기서 **`restricted`** 플래그는 `/usr/libexec` 디렉토리가 SIP로 보호되고 있음을 나타냅니다. SIP로 보호된 디렉토리에서는 파일을 생성, 수정 또는 삭제할 수 없습니다.

또한, 파일에 **`com.apple.rootless`** 확장 **속성**이 포함되어 있다면 해당 파일도 **SIP로 보호**됩니다.

**SIP는 루트 권한으로 수행되는 다른 작업도 제한**합니다. 예를 들어:

* 신뢰할 수 없는 커널 확장을 로드하는 것
* Apple 서명된 프로세스의 작업 포트 가져오기
* NVRAM 변수 수정
* 커널 디버깅 허용

옵션은 nvram 변수로 유지되며, 비트 플래그로 표시됩니다(Intel의 경우 `csr-active-config`, ARM의 경우 부팅된 Device Tree에서 `lp-sip0`로 읽힘). XNU 소스 코드의 `csr.sh`에서 플래그를 찾을 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### SIP 상태

다음 명령을 사용하여 시스템에서 SIP가 활성화되었는지 확인할 수 있습니다:
```bash
csrutil status
```
SIP를 비활성화해야 하는 경우, 컴퓨터를 복구 모드로 재시작해야 합니다 (시작 중에 Command+R을 누르세요). 그런 다음 다음 명령을 실행하세요:
```bash
csrutil disable
```
SIP를 활성화한 상태로 디버깅 보호 기능을 제거하려면 다음을 수행할 수 있습니다:
```bash
csrutil enable --without debug
```
### 기타 제한 사항

- **사인되지 않은 커널 확장자**(kext)의 로딩을 금지하여 확인된 확장자만 시스템 커널과 상호 작용하도록 합니다.
- macOS 시스템 프로세스의 **디버깅을 방지**하여 무단 접근 및 수정으로부터 핵심 시스템 구성 요소를 보호합니다.
- dtrace와 같은 **도구가 시스템 프로세스를 검사하는 것을 방해**하여 시스템 운영의 무결성을 더욱 보호합니다.

**[이 발표에서 SIP 정보에 대해 자세히 알아보세요](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship).**

## SIP 우회

SIP 우회를 통해 공격자는 다음을 수행할 수 있습니다:

- **사용자 데이터에 접근**: 모든 사용자 계정에서 메일, 메시지 및 Safari 기록과 같은 민감한 사용자 데이터를 읽을 수 있습니다.
- **TCC 우회**: TCC(투명성, 동의 및 제어) 데이터베이스를 직접 조작하여 웹캠, 마이크 및 기타 리소스에 무단 액세스 권한을 부여할 수 있습니다.
- **지속성 확보**: SIP로 보호된 위치에 악성 소프트웨어를 배치하여 루트 권한으로도 제거할 수 없도록 만듭니다. 이는 악성 소프트웨어 제거 도구(MRT)를 조작할 수 있는 잠재력도 포함됩니다.
- **커널 확장자 로딩**: 추가적인 보호 기능이 있지만, SIP 우회는 사인되지 않은 커널 확장자를 로딩하는 과정을 단순화합니다.

### 설치 프로그램 패키지

**Apple의 인증서로 서명된 설치 프로그램 패키지**는 SIP의 보호 기능을 우회할 수 있습니다. 따라서 표준 개발자가 서명한 패키지도 SIP로 보호된 디렉터리를 수정하려고 시도하면 차단됩니다.

### SIP 파일이 존재하지 않을 경우

잠재적인 루프홀은 **`rootless.conf`에 지정된 파일이 현재 존재하지 않는 경우** 해당 파일을 생성할 수 있다는 것입니다. 악성 소프트웨어는 시스템에 **지속성을 확립**하기 위해 이를 악용할 수 있습니다. 예를 들어, 악성 프로그램은 `rootless.conf`에는 나열되어 있지만 실제로는 존재하지 않는 `/System/Library/LaunchDaemons`에 .plist 파일을 생성할 수 있습니다.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
**`com.apple.rootless.install.heritable`** 권한은 SIP 우회를 허용합니다.
{% endhint %}

#### Shrootless

[**이 블로그 게시물의 연구원들**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)은 macOS의 시스템 무결성 보호(SIP) 메커니즘인 'Shrootless' 취약점을 발견했습니다. 이 취약점은 **`system_installd`** 데몬을 중심으로 합니다. 이 데몬은 **`com.apple.rootless.install.heritable`**라는 권한을 가지고 있으며, 이를 통해 자식 프로세스 중 어느 것이든 SIP의 파일 시스템 제한을 우회할 수 있습니다.

**`system_installd`** 데몬은 **Apple**에서 서명한 패키지(.pkg 파일)를 설치합니다.

연구원들은 Apple에서 서명한 패키지(.pkg 파일)를 설치하는 동안, 패키지에 포함된 **후속 설치 스크립트**를 **`system_installd`**가 실행한다는 것을 발견했습니다. 이 스크립트는 기본 쉘인 **`zsh`**에 의해 실행되며, 비대화식 모드에서도 **`/etc/zshenv`** 파일에서 명령을 자동으로 실행합니다. 이 동작은 공격자에 의해 악용될 수 있습니다. 악성 `/etc/zshenv` 파일을 생성하고 **`system_installd`가 `zsh`를 호출**할 때까지 기다린 다음, 장치에서 임의의 작업을 수행할 수 있습니다.

또한, **`/etc/zshenv`는 SIP 우회뿐만 아니라 일반적인 공격 기술로 사용될 수 있다는 것**이 발견되었습니다. 각 사용자 프로필에는 `~/.zshenv` 파일이 있으며, 이 파일은 `/etc/zshenv`와 동일한 방식으로 작동하지만 루트 권한이 필요하지 않습니다. 이 파일은 `zsh`가 시작될 때마다 트리거되는 지속성 메커니즘으로 사용되거나 권한 상승 메커니즘으로 사용될 수 있습니다. 관리자 사용자가 `sudo -s` 또는 `sudo <command>`를 사용하여 루트로 상승하는 경우, `~/.zshenv` 파일이 트리거되어 실제로 루트로 상승됩니다.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)에서는 동일한 **`system_installd`** 프로세스가 여전히 악용될 수 있다는 것이 발견되었습니다. 이는 **`/tmp` 내부에 SIP로 보호된 임의의 이름을 가진 폴더에 후속 설치 스크립트를 넣는 것**이었습니다. 문제는 **`/tmp` 자체가 SIP로 보호되지 않기 때문에**, 가상 이미지를 마운트한 다음 **설치 프로그램**이 거기에 **후속 설치 스크립트**를 넣고 가상 이미지를 **언마운트**하고 **모든 폴더를 다시 생성**하고 **페이로드**가 포함된 **후속 설치 스크립트**를 추가할 수 있다는 것입니다.

#### [fsck\_cs 유틸리티](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

**`fsck_cs`**가 **심볼릭 링크**를 따를 수 있는 능력 때문에 중요한 파일을 손상시키는 오류가 발견되었습니다. 구체적으로, 공격자는 _`/dev/diskX`_에서 파일 `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`로의 링크를 만들었습니다. _`/dev/diskX`_에서 **`fsck_cs`**를 실행하면 `Info.plist`가 손상됩니다. 이 파일의 무결성은 운영 체제의 SIP(System Integrity Protection)에 매우 중요하며, 커널 확장자의 로딩을 제어합니다. 손상된 후에는 SIP의 커널 제외 기능이 손상됩니다.

이 취약점을 악용하기 위한 명령어는 다음과 같습니다:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
이 취약점의 악용은 심각한 영향을 가집니다. 일반적으로 커널 확장의 권한을 관리하는 `Info.plist` 파일이 효과가 없어집니다. 이는 `AppleHWAccess.kext`와 같은 특정 확장을 블랙리스트에 추가할 수 없음을 의미합니다. 따라서 SIP의 제어 메커니즘이 정상적으로 작동하지 않으면 이 확장이 로드되어 시스템의 RAM에 무단으로 읽기 및 쓰기 액세스 권한을 부여할 수 있습니다.


#### [SIP 보호된 폴더 위에 마운트](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**SIP 보호된 폴더 위에 새 파일 시스템을 마운트하여 보호를 우회**하는 것이 가능했습니다.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader 우회 (2016)](https://objective-see.org/blog/blog\_0x14.html)

시스템은 `Install macOS Sierra.app` 내에 포함된 설치 디스크 이미지를 이용하여 OS를 업그레이드하기 위해 `bless` 유틸리티를 사용하여 부팅됩니다. 사용된 명령은 다음과 같습니다:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
이 프로세스의 보안은 공격자가 부팅하기 전에 업그레이드 이미지 (`InstallESD.dmg`)를 변경하는 경우 침해될 수 있습니다. 이 전략은 악성 버전 (`libBaseIA.dylib`)으로 동적 로더 (dyld)를 대체하는 것을 포함합니다. 이 대체로 인해 설치 프로그램이 시작될 때 공격자의 코드가 실행됩니다.

공격자의 코드는 업그레이드 프로세스 중에 제어를 얻으며, 설치 프로그램에 대한 시스템의 신뢰를 악용합니다. 공격은 `InstallESD.dmg` 이미지를 메소드 스위즐링을 통해 변경함으로써 진행됩니다. 특히 `extractBootBits` 메소드를 대상으로 합니다. 이를 통해 디스크 이미지가 사용되기 전에 악성 코드를 주입할 수 있습니다.

또한, `InstallESD.dmg` 내에는 업그레이드 코드의 루트 파일 시스템으로 작동하는 `BaseSystem.dmg`가 있습니다. 이에 동적 라이브러리를 주입함으로써 악성 코드가 OS 수준 파일을 변경할 수 있는 프로세스 내에서 작동할 수 있습니다. 이는 시스템 침해 가능성을 크게 증가시킵니다.


#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk)에서 이야기하는 것처럼 **`systemmigrationd`** (SIP 우회 가능)가 **bash**와 **perl** 스크립트를 실행하는 것을 보여줍니다. 이는 env 변수 **`BASH_ENV`**와 **`PERL5OPT`**를 통해 악용될 수 있습니다.

### **com.apple.rootless.install**

{% hint style="danger" %}
**`com.apple.rootless.install`** 권한은 SIP 우회를 허용합니다.
{% endhint %}

`com.apple.rootless.install` 권한은 macOS에서 System Integrity Protection (SIP) 우회를 허용하는 것으로 알려져 있습니다. 이는 특히 [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)와 관련하여 언급되었습니다.

특정한 경우에는 `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc`에 위치한 시스템 XPC 서비스가 이 권한을 가지고 있습니다. 이로 인해 관련 프로세스는 SIP 제약을 우회할 수 있습니다. 또한, 이 서비스는 보안 조치를 강제하지 않고 파일을 이동할 수 있는 메소드를 제공합니다.


## Sealed System Snapshots

Sealed System Snapshots는 Apple이 **macOS Big Sur (macOS 11)**에서 도입한 기능으로, **System Integrity Protection (SIP)** 메커니즘의 일부로 추가적인 보안 및 시스템 안정성을 제공합니다. 이는 사실상 시스템 볼륨의 읽기 전용 버전입니다.

자세한 내용은 다음과 같습니다:

1. **불변 시스템**: Sealed System Snapshots는 macOS 시스템 볼륨을 "불변"하게 만들어 변경할 수 없도록 합니다. 이는 보안이나 시스템 안정성을 저해할 수 있는 무단 또는 우발적인 시스템 변경을 방지합니다.
2. **시스템 소프트웨어 업데이트**: macOS 업데이트 또는 업그레이드를 설치할 때마다 macOS는 새로운 시스템 스냅샷을 생성합니다. macOS 시작 볼륨은 이 새로운 스냅샷으로 전환하기 위해 **APFS (Apple File System)**를 사용합니다. 업데이트 적용 프로세스 전체가 이전 스냅샷으로 롤백할 수 있기 때문에 업데이트 과정이 더 안전하고 신뢰할 수 있습니다.
3. **데이터 분리**: macOS Catalina에서 도입된 데이터 및 시스템 볼륨 분리 개념과 함께 Sealed System Snapshot 기능은 모든 데이터와 설정이 별도의 "**Data**" 볼륨에 저장되도록 보장합니다. 이 분리는 데이터를 시스템으로부터 독립시키므로 시스템 업데이트 프로세스를 간소화하고 시스템 보안을 강화합니다.

이러한 스냅샷은 macOS에서 자동으로 관리되며 APFS의 공간 공유 기능 덕분에 디스크에 추가 공간을 차지하지 않습니다. 또한, 이러한 스냅샷은 전체 시스템의 사용자 접근 가능한 백업인 **Time Machine 스냅샷**과는 다릅니다.

### 스냅샷 확인

명령어 **`diskutil apfs list`**는 **APFS 볼륨의 세부 정보**와 레이아웃을 나열합니다:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

이전 출력에서는 **사용자 접근 가능한 위치**가 `/System/Volumes/Data` 아래에 마운트되어 있는 것을 볼 수 있습니다.

또한, **macOS 시스템 볼륨 스냅샷**은 `/`에 마운트되어 있으며 **봉인**되어 있습니다 (OS에 의해 암호화 서명됨). 따라서 SIP가 우회되고 수정되면 **OS가 더 이상 부팅되지 않습니다**.

봉인이 활성화되었는지 확인하려면 다음을 실행하면 됩니다:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
또한, 스냅샷 디스크는 **읽기 전용**으로 마운트됩니다:
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
