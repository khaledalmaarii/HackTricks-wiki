# macOS SIP

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

- **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**당했는지 무료로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난당한 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료로** 시도해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

***

## **기본 정보**

macOS의 **시스템 무결성 보호 (SIP)**는 가장 권한이 높은 사용자조차도 핵심 시스템 폴더에 무단으로 변경을 가하는 것을 방지하기 위해 설계된 메커니즘입니다. 이 기능은 보호된 영역에서 파일을 추가, 수정 또는 삭제하는 것과 같은 작업을 제한하여 시스템의 무결성을 유지하는 데 중요한 역할을 합니다. SIP에 의해 보호되는 주요 폴더는 다음과 같습니다:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

SIP의 동작을 규정하는 규칙은 **`/System/Library/Sandbox/rootless.conf`**에 위치한 구성 파일에서 정의됩니다. 이 파일에서 별표(\*)로 접두사가 붙은 경로는 엄격한 SIP 제한의 예외로 표시됩니다.

아래 예시를 살펴보세요:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
이 스니펫은 SIP가 일반적으로 **`/usr`** 디렉토리를 보호하지만, 특정 하위 디렉토리(``/usr/libexec/cups`, `/usr/local`, `/usr/share/man`)는 경로 앞에 별표(\*)가 표시되어 수정이 허용된다는 것을 시사합니다.

디렉토리 또는 파일이 SIP에 의해 보호되는지 확인하려면 **`ls -lOd`** 명령을 사용하여 **`restricted`** 또는 **`sunlnk`** 플래그의 존재를 확인할 수 있습니다. 예를 들어:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
이 경우, **`sunlnk`** 플래그는 `/usr/libexec/cups` 디렉토리 자체가 **삭제할 수 없음**을 나타내지만, 그 내부 파일은 생성, 수정 또는 삭제할 수 있습니다.

반면에:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
여기서 **`restricted`** 플래그는 `/usr/libexec` 디렉토리가 SIP로 보호되었음을 나타냅니다. SIP로 보호된 디렉토리에서는 파일을 생성, 수정 또는 삭제할 수 없습니다.

또한, 파일이 **`com.apple.rootless`** 확장 **속성**을 포함하고 있는 경우 해당 파일도 **SIP로 보호**됩니다.

**SIP는 또한 다른 루트 작업을 제한**합니다:

* 신뢰할 수 없는 커널 확장 기능 로드
* Apple 서명된 프로세스에 대한 작업 포트 가져오기
* NVRAM 변수 수정
* 커널 디버깅 허용

옵션은 비트 플래그로 nvram 변수에 유지됩니다(Intel의 `csr-active-config` 및 ARM의 부팅된 Device Tree에서 `lp-sip0`를 읽습니다). `csr.sh`에서 XNU 소스 코드에서 플래그를 찾을 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP 상태

다음 명령어로 시스템에서 SIP가 활성화되어 있는지 확인할 수 있습니다:
```bash
csrutil status
```
만약 SIP를 비활성화해야 한다면, 컴퓨터를 복구 모드로 재부팅해야 합니다 (부팅 중에 Command+R을 누름), 그리고 다음 명령어를 실행하십시오:
```bash
csrutil disable
```
만약 SIP를 활성화한 상태에서 디버깅 보호를 제거하고 싶다면 다음을 사용할 수 있습니다:
```bash
csrutil enable --without debug
```
### 기타 제한 사항

* **사인되지 않은 커널 익스텐션**(kext)의 로딩을 금지하여 확인된 익스텐션이 시스템 커널과 상호작용하도록 합니다.
* macOS 시스템 프로세스의 디버깅을 방지하여 핵심 시스템 구성 요소가 무단 액세스와 수정으로부터 안전하게 합니다.
* dtrace와 같은 도구가 시스템 프로세스를 검사하는 것을 금지하여 시스템 작동의 무결성을 더욱 보호합니다.

[**이 대화에서 SIP 정보에 대해 자세히 알아보기**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

## SIP 우회

SIP 우회는 공격자가 다음을 수행할 수 있게 합니다:

* **사용자 데이터 액세스**: 모든 사용자 계정에서 메일, 메시지, Safari 기록과 같은 민감한 사용자 데이터를 읽을 수 있습니다.
* **TCC 우회**: TCC(투명성, 동의 및 제어) 데이터베이스를 직접 조작하여 웹캠, 마이크 및 기타 리소스에 무단 액세스를 부여할 수 있습니다.
* **지속성 확립**: SIP로 보호된 위치에 악성 소프트웨어를 배치하여 루트 권한으로도 제거할 수 없게 만듭니다. 이는 Malware Removal Tool (MRT)를 조작할 수 있는 잠재적인 가능성을 포함합니다.
* **커널 익스텐션 로드**: 추가적인 보호장치가 있지만, SIP 우회는 사인되지 않은 커널 익스텐션을 로드하는 과정을 간단화합니다.

### 설치 프로그램

**Apple의 인증서로 서명된 설치 프로그램**은 이러한 보호장치를 우회할 수 있습니다. 이는 표준 개발자가 서명한 패키지라도 SIP로 보호된 디렉토리를 수정하려고 시도하면 차단될 것을 의미합니다.

### 존재하지 않는 SIP 파일

잠재적인 구멍 중 하나는 **`rootless.conf`에 지정된 파일이 현재 존재하지 않는 경우** 해당 파일을 생성할 수 있다는 것입니다. 악성 소프트웨어는 시스템에 **지속성을 확립**하기 위해 이를 악용할 수 있습니다. 예를 들어, 악의적인 프로그램이 `/System/Library/LaunchDaemons`에 .plist 파일을 생성할 수 있습니다. `rootless.conf`에는 목록에는 있지만 실제로는 존재하지 않을 때 이를 이용할 수 있습니다.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
**`com.apple.rootless.install.heritable`** 권한은 SIP 우회를 허용합니다.
{% endhint %}

#### [CVE-2019-8561](https://objective-see.org/blog/blog\_0x42.html) <a href="#cve" id="cve"></a>

시스템이 코드 서명을 확인한 후 **설치 프로그램 패키지를 교체**할 수 있는 것이 발견되었고, 그 결과 시스템은 원래의 대신 악성 패키지를 설치합니다. 이러한 작업이 **`system_installd`**에 의해 수행되었기 때문에 SIP를 우회할 수 있습니다.

#### [CVE-2020–9854](https://objective-see.org/blog/blog\_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

마운트된 이미지나 외부 드라이브에서 패키지를 설치하면 **설치 프로그램**이 **해당 파일 시스템**에서 이진 파일을 **실행**하게 되어 SIP로 보호된 위치가 아닌 곳에서 실행됩니다. 이는 **`system_installd`**가 임의의 이진 파일을 실행하도록 만듭니다.

#### CVE-2021-30892 - Shrootless

[**이 블로그 게시물의 연구원들**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)은 macOS의 시스템 무결성 보호(SIP) 메커니즘에서 'Shrootless' 취약점이라고 불리는 취약점을 발견했습니다. 이 취약점은 **`system_installd`** 데몬을 중심으로 하며, 이 데몬은 **`com.apple.rootless.install.heritable`** 권한을 가지고 있어 자식 프로세스 중 어느 것이든 SIP의 파일 시스템 제한을 우회할 수 있습니다.

**`system_installd`** 데몬은 **Apple**에서 서명된 패키지(.pkg 파일)를 설치합니다.

연구원들은 Apple에서 서명된 패키지(.pkg 파일)를 설치하는 동안 **`system_installd`**가 패키지에 포함된 **포스트-설치** 스크립트를 실행한다는 것을 발견했습니다. 이러한 스크립트는 기본 쉘인 **`zsh`**에 의해 실행되며, 비대화식 모드에서도 존재한다면 **`/etc/zshenv`** 파일에서 명령을 자동으로 실행합니다. 이 동작은 공격자에 의해 악용될 수 있습니다: 악성 `/etc/zshenv` 파일을 생성하고 **`system_installd`가 `zsh`를 호출하도록 기다린 후**, 장치에서 임의의 작업을 수행할 수 있습니다.

또한 **`/etc/zshenv`를 SIP 우회뿐만 아니라 일반적인 공격 기술로 사용할 수 있다는 것**이 발견되었습니다. 각 사용자 프로필에는 루트 권한이 필요하지 않지만 `~/.zshenv` 파일이 있으며, 이 파일은 `zsh`가 시작될 때마다 트리거되거나 권한 상승 메커니즘으로 사용될 수 있습니다. 관리자 사용자가 `sudo -s` 또는 `sudo <command>`를 사용하여 루트로 상승하면 `~/.zshenv` 파일이 트리거되어 사실상 루트로 상승합니다.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)에서는 동일한 **`system_installd`** 프로세스가 **`/tmp` 내 SIP로 보호된 임의의 이름의 폴더에 포스트-설치 스크립트를 넣는** 문제가 발견되었습니다. **`/tmp` 자체는 SIP로 보호되지 않기 때문에** 가상 이미지를 마운트하고, 그곳에 **포스트-설치 스크립트**를 넣은 후 가상 이미지를 언마운트하고, 모든 **폴더를 다시 생성**하고 **페이로드를 실행하는 포스트 설치** 스크립트를 추가할 수 있었습니다.

#### [fsck\_cs 유틸리티](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

**`fsck_cs`**가 **심볼릭 링크**를 따르는 능력으로 인해 중요한 파일을 손상시키도록 속이는 취약점이 식별되었습니다. 구체적으로, 공격자는 _`/dev/diskX`_에서 파일 `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`로의 링크를 작성했습니다. _`/dev/diskX`_에서 **`fsck_cs`**를 실행하면 `Info.plist`가 손상됩니다. 이 파일의 무결성은 커널 익스텐션의 로딩을 제어하는 SIP(System Integrity Protection)에 중요합니다. 한 번 손상되면 SIP의 커널 제외 관리 기능이 손상됩니다.
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
이 취약점의 악용은 심각한 영향을 미칩니다. 일반적으로 커널 확장 프로그램의 권한을 관리하는 `Info.plist` 파일이 효과가 없어집니다. 이는 `AppleHWAccess.kext`와 같은 특정 확장 프로그램을 블랙리스트에 추가할 수 없게 되는 것을 포함합니다. 결과적으로 SIP의 제어 메커니즘이 제대로 작동하지 않으면 이 확장 프로그램이 로드되어 시스템 RAM에 대한 무단 읽기 및 쓰기 액세스 권한이 부여될 수 있습니다.

#### [SIP 보호 폴더 위에 마운트](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**SIP 보호 폴더 위에 새 파일 시스템을 마운트하여 보호를 우회**하는 것이 가능했습니다.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog\_0x14.html)

시스템은 `Install macOS Sierra.app` 내에 포함된 설치 디스크 이미지에서 부팅하도록 설정되어 있어 OS를 업그레이드하기 위해 `bless` 유틸리티를 활용합니다. 사용된 명령은 다음과 같습니다:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
해커가 부팅하기 전에 업그레이드 이미지(`InstallESD.dmg`)를 변경하면 이 프로세스의 보안이 침해될 수 있습니다. 이 전략은 악의적인 버전(`libBaseIA.dylib`)의 동적 로더(dyld)로 동적 로더를 대체하는 것을 포함합니다. 이 교체로 인해 설치 프로그램이 시작될 때 해커의 코드가 실행됩니다.

해커의 코드는 업그레이드 프로세스 중에 제어를 얻으며, 시스템이 설치 프로그램에 대한 신뢰를 악용합니다. 공격은 `extractBootBits` 메소드를 특히 대상으로 한 메소드 스위즐링을 통해 `InstallESD.dmg` 이미지를 변경함으로써 진행됩니다. 이를 통해 디스크 이미지가 사용되기 전에 악의적인 코드를 삽입할 수 있습니다.

또한 `InstallESD.dmg` 내에는 업그레이드 코드의 루트 파일 시스템 역할을 하는 `BaseSystem.dmg`가 있습니다. 여기에 동적 라이브러리를 삽입하면 악의적인 코드가 OS 수준 파일을 변경할 수 있는 프로세스 내에서 작동할 수 있어 시스템 침해 가능성이 크게 증가합니다.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk)에서 이루어진 이 발표에서는 SIP를 우회할 수 있는 **`systemmigrationd`**가 **bash** 및 **perl** 스크립트를 실행하는 것을 보여줍니다. 이는 환경 변수 **`BASH_ENV`** 및 **`PERL5OPT`**를 통해 악용될 수 있습니다.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

[**이 블로그 게시물에 자세히 나와 있듯이**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `InstallAssistant.pkg` 패키지의 `postinstall` 스크립트가 실행되었습니다.
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
### **com.apple.rootless.install**

{% hint style="danger" %}
엔타이틀먼트 **`com.apple.rootless.install`**은 SIP 우회를 허용합니다.
{% endhint %}

엔타이틀먼트 `com.apple.rootless.install`은 macOS에서 시스템 무결성 보호 (SIP)를 우회하는 데 사용됩니다. 이것은 특히 [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)와 관련하여 언급되었습니다.

특정한 경우에는 `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc`에 위치한 시스템 XPC 서비스가 이 엔타이틀먼트를 가지고 있습니다. 이를 통해 관련 프로세스가 SIP 제약을 우회할 수 있습니다. 또한, 이 서비스는 보안 조치를 적용하지 않고 파일 이동을 허용하는 방법을 제공합니다.

## 봉인된 시스템 스냅샷

봉인된 시스템 스냅샷은 **macOS Big Sur (macOS 11)**에서 도입된 기능으로, **시스템 무결성 보호 (SIP)** 메커니즘의 일부로 시스템 보안과 안정성을 추가로 제공합니다. 이들은 본질적으로 시스템 볼륨의 읽기 전용 버전입니다.

다음은 더 자세한 내용입니다:

1. **불변 시스템**: 봉인된 시스템 스냅샷은 macOS 시스템 볼륨을 "불변"으로 만들어 수정할 수 없게 합니다. 이를 통해 보안이나 시스템 안정성을 compromise할 수 있는 무단 또는 우연한 변경을 방지합니다.
2. **시스템 소프트웨어 업데이트**: macOS 업데이트나 업그레이드를 설치할 때, macOS는 새로운 시스템 스냅샷을 생성합니다. macOS 시작 볼륨은 이 새로운 스냅샷으로 전환하기 위해 **APFS (Apple File System)**를 사용합니다. 시스템은 업데이트 적용 과정이 이전 스냅샷으로 언제든지 복원할 수 있도록 하여 업데이트 과정이 더 안전하고 신뢰할 수 있게 됩니다.
3. **데이터 분리**: macOS Catalina에서 소개된 데이터 및 시스템 볼륨 분리 개념과 함께, 봉인된 시스템 스냅샷 기능은 모든 데이터와 설정이 별도의 "**데이터**" 볼륨에 저장되도록 합니다. 이 분리로 인해 데이터가 시스템과 독립되어 시스템 업데이트 과정이 간소화되고 시스템 보안이 강화됩니다.

이러한 스냅샷은 macOS에서 자동으로 관리되며, APFS의 공간 공유 기능 덕분에 디스크에 추가 공간을 차지하지 않습니다. 또한 이러한 스냅샷은 전체 시스템의 **타임 머신 스냅샷**과는 다르며 사용자가 접근할 수 있는 백업입니다.

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

이전 출력에서 **사용자 접근 가능한 위치**가 `/System/Volumes/Data` 아래에 마운트되어 있는 것을 볼 수 있습니다.

또한, **macOS 시스템 볼륨 스냅샷**은 `/`에 마운트되어 있으며 **봉인**되어 있습니다 (OS에 의해 암호화 서명됨). 따라서 SIP가 우회되고 수정된 경우, **OS는 더 이상 부팅되지 않습니다**.

봉인이 활성화되어 있는지 **확인**하려면 다음을 실행할 수 있습니다:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
게다가, 스냅샷 디스크는 **읽기 전용**으로 마운트됩니다:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 활용한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**당했는지 확인하는 **무료** 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난당한 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 **무료**로 엔진을 시험해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
