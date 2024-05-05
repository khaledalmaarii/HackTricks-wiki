# macOS 파일, 폴더, 이진 파일 및 메모리

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로**부터 **히어로**로 **AWS 해킹** 배우기!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 파일 계층 구조

* **/Applications**: 설치된 앱이 여기에 있어야 합니다. 모든 사용자가 액세스할 수 있습니다.
* **/bin**: 명령 줄 이진 파일
* **/cores**: 코어 덤프를 저장하는 데 사용됩니다.
* **/dev**: 모든 것이 파일로 처리되므로 하드웨어 장치가 여기에 저장될 수 있습니다.
* **/etc**: 구성 파일
* **/Library**: 많은 하위 디렉토리와 로그와 관련된 파일이 여기에 있습니다. 루트 및 각 사용자 디렉토리에 Library 폴더가 있습니다.
* **/private**: 문서화되지 않았지만 언급된 많은 폴더가 private 디렉토리로의 심볼릭 링크입니다.
* **/sbin**: 필수 시스템 이진 파일 (관리와 관련)
* **/System**: OS X를 실행하기 위한 파일입니다. 여기에는 주로 Apple 특정 파일만 있어야 합니다(서드 파티 파일이 아님).
* **/tmp**: 파일은 3일 후에 삭제됩니다 (/private/tmp로의 소프트 링크입니다).
* **/Users**: 사용자의 홈 디렉토리입니다.
* **/usr**: 구성 및 시스템 이진 파일
* **/var**: 로그 파일
* **/Volumes**: 마운트된 드라이브가 여기에 나타납니다.
* **/.vol**: `stat a.txt`를 실행하면 `16777223 7545753 -rw-r--r-- 1 username wheel ...`과 같은 내용을 얻을 수 있습니다. 여기서 첫 번째 숫자는 파일이 존재하는 볼륨의 ID 번호이고 두 번째 숫자는 inode 번호입니다. 이 정보를 사용하여 `cat /.vol/16777223/7545753`를 실행하여 이 파일의 내용에 액세스할 수 있습니다.

### 애플리케이션 폴더

* **시스템 애플리케이션**은 `/System/Applications`에 위치합니다.
* **설치된** 애플리케이션은 일반적으로 `/Applications` 또는 `~/Applications`에 설치됩니다.
* **애플리케이션 데이터**는 루트로 실행되는 애플리케이션의 경우 `/Library/Application Support`에서, 사용자로 실행되는 애플리케이션의 경우 `~/Library/Application Support`에서 찾을 수 있습니다.
* **루트로 실행해야 하는** **제3자 애플리케이션 데몬**은 일반적으로 `/Library/PrivilegedHelperTools/`에 위치합니다.
* **샌드박스** 앱은 `~/Library/Containers` 폴더로 매핑됩니다. 각 앱은 애플리케이션 번들 ID에 따라 이름이 지정된 폴더를 가지고 있습니다 (`com.apple.Safari`).
* **커널**은 `/System/Library/Kernels/kernel`에 있습니다.
* **Apple의 커널 확장**은 `/System/Library/Extensions`에 있습니다.
* **제3자 커널 확장**은 `/Library/Extensions`에 저장됩니다.

### 민감한 정보가 포함된 파일

MacOS는 비밀번호와 같은 정보를 여러 위치에 저장합니다:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### 취약한 pkg 설치 프로그램

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X 특정 확장자

* **`.dmg`**: Apple 디스크 이미지 파일은 설치 프로그램에서 매우 빈번하게 사용됩니다.
* **`.kext`**: 특정 구조를 따라야 하며 드라이버의 OS X 버전입니다. (번들입니다)
* **`.plist`**: XML 또는 이진 형식으로 정보를 저장하는 속성 목록으로도 알려져 있습니다.
* XML 또는 이진 형식일 수 있습니다. 이진 파일은 다음과 같이 읽을 수 있습니다:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: 디렉토리 구조를 따르는 Apple 애플리케이션 (번들입니다).
* **`.dylib`**: 동적 라이브러리 (Windows DLL 파일과 유사)
* **`.pkg`**: xar (eXtensible Archive 형식)와 동일합니다. installer 명령을 사용하여 이러한 파일의 내용을 설치할 수 있습니다.
* **`.DS_Store`**: 각 디렉토리에 있는 이 파일은 디렉토리의 속성과 사용자 정의를 저장합니다.
* **`.Spotlight-V100`**: 이 폴더는 시스템의 모든 볼륨의 루트 디렉토리에 나타납니다.
* **`.metadata_never_index`**: 이 파일이 볼륨의 루트에 있으면 Spotlight는 해당 볼륨을 색인화하지 않습니다.
* **`.noindex`**: 이 확장자가 있는 파일 및 폴더는 Spotlight에 의해 색인화되지 않습니다.
* **`.sdef`**: 번들 내부의 파일로, AppleScript를 통해 애플리케이션과 상호 작용하는 방법을 지정합니다.

### macOS 번들

번들은 **Finder에서 객체처럼 보이는 디렉토리**입니다 (예: `*.app` 파일).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld 공유 라이브러리 캐시 (SLC)

macOS (및 iOS)에서 모든 시스템 공유 라이브러리, 프레임워크 및 dylib와 같은 파일은 **단일 파일인** **dyld 공유 캐시**로 **결합**됩니다. 이렇게 하면 코드를 더 빨리 로드할 수 있어 성능이 향상됩니다.

이는 macOS에서 `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`에 있으며 이전 버전에서는 **`/System/Library/dyld/`**에서 **공유 캐시**를 찾을 수 있습니다.\
iOS에서는 **`/System/Library/Caches/com.apple.dyld/`**에서 찾을 수 있습니다.

dyld 공유 캐시와 유사하게, 커널 및 커널 확장도 부팅 시간에 로드되는 커널 캐시로 컴파일됩니다.

단일 파일 dylib 공유 캐시에서 라이브러리를 추출하려면 이전에 [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) 이진 파일을 사용할 수 있었지만 현재는 작동하지 않을 수 있습니다. 대신 [**dyldextractor**](https://github.com/arandomdev/dyldextractor)를 사용할 수 있습니다:

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

{% hint style="success" %}
`dyld_shared_cache_util` 도구가 작동하지 않더라도 **공유 dyld 이진 파일을 Hopper에 전달**하여 Hopper가 모든 라이브러리를 식별하고 **조사할 라이브러리를 선택**할 수 있습니다.
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

일부 추출 도구는 dylibs가 하드 코딩된 주소로 사전 링크되어 있기 때문에 작동하지 않을 수 있으며, 따라서 알 수 없는 주소로 이동할 수 있습니다.

{% hint style="success" %}
또한 Xcode에서 에뮬레이터를 사용하여 macOS의 다른 \*OS 장치의 공유 라이브러리 캐시를 다운로드할 수 있습니다. 이들은 다음 위치에 다운로드됩니다: `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, 예:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`
{% endhint %}

### SLC 매핑

**`dyld`**는 SLC가 매핑되었는지를 알기 위해 시스콜 **`shared_region_check_np`**를 사용하고 SLC를 매핑하기 위해 **`shared_region_map_and_slide_np`**를 사용합니다.

SLC가 처음 사용될 때 슬라이드되더라도, 모든 **프로세스**가 **동일한 사본**을 사용하므로, 시스템에서 프로세스를 실행할 수 있는 공격자가 ASLR 보호를 **제거**합니다. 이것은 실제로 과거에 악용되었으며 공유 영역 페이저로 수정되었습니다.

브랜치 풀은 이미지 매핑 사이에 작은 공간을 만드는 작은 Mach-O dylibs입니다. 이를 통해 함수를 중첩하는 것이 불가능해집니다.

### SLC 재정의

환경 변수를 사용하여:

* **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> 새로운 공유 라이브러리 캐시를 로드할 수 있게 합니다.
* **`DYLD_SHARED_CACHE_DIR=avoid`** 및 심볼릭 링크를 사용하여 라이브러리를 실제 공유 캐시로 교체합니다 (추출해야 함).

## 특수 파일 권한

### 폴더 권한

**폴더**에서 **읽기**는 **목록**을 허용하고, **쓰기**는 **삭제** 및 **파일 작성**을 허용하며, **실행**은 **디렉터리 탐색**을 허용합니다. 따라서 예를 들어, 사용자가 **실행 권한이 없는 디렉토리**에 있는 파일의 **읽기 권한**을 가지고 있으면 파일을 **읽을 수 없습니다**.

### 플래그 수정자

파일에 설정할 수 있는 일부 플래그가 있으며 파일의 동작을 다르게 만들 수 있습니다. `ls -lO /path/directory`로 디렉토리 내의 파일의 플래그를 확인할 수 있습니다.

* **`uchg`**: **uchange** 플래그로 알려진 것은 **파일을 변경하거나 삭제하는 모든 작업을 방지**합니다. 이를 설정하려면: `chflags uchg file.txt`
* 루트 사용자는 **플래그를 제거**하고 파일을 수정할 수 있습니다.
* **`restricted`**: 이 플래그는 파일을 **SIP로 보호**합니다 (이 플래그를 파일에 추가할 수 없음).
* **`Sticky bit`**: sticky bit가 있는 디렉토리의 경우 **디렉토리 소유자 또는 루트만 파일 이름을 바꾸거나 삭제**할 수 있습니다. 일반적으로 이것은 /tmp 디렉토리에 설정되어 일반 사용자가 다른 사용자의 파일을 삭제하거나 이동하는 것을 방지합니다.

모든 플래그는 파일 `sys/stat.h`에서 찾을 수 있으며 (`mdfind stat.h | grep stat.h`를 사용하여 찾을 수 있음) 다음과 같습니다:

* `UF_SETTABLE` 0x0000ffff: 소유자 변경 가능한 플래그 마스크.
* `UF_NODUMP` 0x00000001: 파일을 덤프하지 마십시오.
* `UF_IMMUTABLE` 0x00000002: 파일을 변경할 수 없음.
* `UF_APPEND` 0x00000004: 파일에 쓸 때는 추가만 가능합니다.
* `UF_OPAQUE` 0x00000008: 연합에 대해 디렉터리가 불투명합니다.
* `UF_COMPRESSED` 0x00000020: 파일이 압축됨 (일부 파일 시스템).
* `UF_TRACKED` 0x00000040: 이 플래그가 설정된 파일에 대해 삭제/이름 바꾸기에 대한 알림이 없음.
* `UF_DATAVAULT` 0x00000080: 읽기 및 쓰기에 대한 권한이 필요합니다.
* `UF_HIDDEN` 0x00008000: 이 항목이 GUI에 표시되지 않아야 함을 나타냄.
* `SF_SUPPORTED` 0x009f0000: 슈퍼 사용자가 지원하는 플래그 마스크.
* `SF_SETTABLE` 0x3fff0000: 슈퍼 사용자 변경 가능한 플래그 마스크.
* `SF_SYNTHETIC` 0xc0000000: 시스템 읽기 전용 합성 플래그 마스크.
* `SF_ARCHIVED` 0x00010000: 파일이 보관됨.
* `SF_IMMUTABLE` 0x00020000: 파일을 변경할 수 없음.
* `SF_APPEND` 0x00040000: 파일에 쓸 때는 추가만 가능합니다.
* `SF_RESTRICTED` 0x00080000: 쓰기에 대한 권한이 필요합니다.
* `SF_NOUNLINK` 0x00100000: 항목을 제거, 이름 변경 또는 마운트할 수 없음.
* `SF_FIRMLINK` 0x00800000: 파일이 firmlink임.
* `SF_DATALESS` 0x40000000: 파일이 데이터 없는 객체임.

### **파일 ACLs**

파일 **ACLs**에는 다른 사용자에게 **더 세분화된 권한**을 할당할 수 있는 **ACE** (액세스 제어 항목)가 포함되어 있습니다.

**디렉토리**에는 다음 권한을 부여할 수 있습니다: `목록`, `검색`, `파일 추가`, `하위 디렉토리 추가`, `하위 항목 삭제`, `하위 항목 삭제`.\
**파일**에는 다음을 할 수 있습니다: `읽기`, `쓰기`, `추가`, `실행`.

파일에 ACL이 포함되어 있으면 권한을 나열할 때 **"+"**를 찾을 수 있습니다.
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
파일의 **ACLs를 읽을 수 있습니다**.
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
**모든 ACL이 있는 파일을 찾을 수 있습니다** (이겁니다. 아주 느립니다):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### 확장 속성

확장 속성은 이름과 원하는 값이 포함되어 있으며 `ls -@`를 사용하여 볼 수 있으며 `xattr` 명령을 사용하여 조작할 수 있습니다. 일반적인 확장 속성은 다음과 같습니다:

- `com.apple.resourceFork`: 리소스 포크 호환성. `filename/..namedfork/rsrc`로도 볼 수 있음
- `com.apple.quarantine`: MacOS: Gatekeeper 격리 메커니즘 (III/6)
- `metadata:*`: MacOS: `_backup_excludeItem` 또는 `kMD*`와 같은 다양한 메타데이터
- `com.apple.lastuseddate` (#PS): 마지막 파일 사용 날짜
- `com.apple.FinderInfo`: MacOS: Finder 정보 (예: 색 태그)
- `com.apple.TextEncoding`: ASCII 텍스트 파일의 텍스트 인코딩 지정
- `com.apple.logd.metadata`: `/var/db/diagnostics`의 파일에서 logd에서 사용됨
- `com.apple.genstore.*`: 세대 저장소 (`/.DocumentRevisions-V100` 파일 시스템 루트에 있음)
- `com.apple.rootless`: MacOS: 시스템 무결성 보호에 의해 파일 레이블 지정에 사용됨 (III/10)
- `com.apple.uuidb.boot-uuid`: 고유 UUID로 부팅 시대의 logd 표시
- `com.apple.decmpfs`: MacOS: 투명 파일 압축 (II/7)
- `com.apple.cprotect`: \*OS: 파일 단위 암호화 데이터 (III/11)
- `com.apple.installd.*`: \*OS: installd에서 사용되는 메타데이터, 예: `installType`, `uniqueInstallID`

### 리소스 포크 | macOS ADS

이는 **MacOS 기계에서 대체 데이터 스트림(ADS)**를 얻는 방법입니다. **com.apple.ResourceFork**라는 확장 속성 내부에 내용을 저장하여 파일 내부에 저장할 수 있습니다. **file/..namedfork/rsrc**에 저장함으로써.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
다음을 사용하여 **이 확장 속성을 포함하는 모든 파일을 찾을 수 있습니다**:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

### decmpfs

확장 속성 `com.apple.decmpfs`는 파일이 암호화되어 저장되었음을 나타냅니다. `ls -l`은 **크기가 0**으로 보고 압축된 데이터가 이 속성 안에 있음을 보고합니다. 파일에 액세스할 때마다 메모리에서 복호화됩니다.

이 속성은 `ls -lO`로 볼 수 있으며 압축된 파일은 `UF_COMPRESSED` 플래그로 태그가 지정됩니다. 압축된 파일이 제거되면 `chflags nocompressed </path/to/file>`로 이 플래그를 제거하면 시스템은 파일이 압축되었다는 것을 알지 못하므로 데이터에 액세스하거나 압축 해제할 수 없습니다 (실제로 비어 있는 것으로 간주합니다).

afscexpand 도구를 사용하여 강제로 파일을 압축 해제할 수 있습니다.

## **Universal binaries &** Mach-o Format

Mac OS 이진 파일은 일반적으로 **universal binaries**로 컴파일됩니다. **Universal binary**는 **동일한 파일 내에서 여러 아키텍처를 지원**할 수 있습니다.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS Process Memory

## macOS 메모리 덤프

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Mac OS의 위험 범주 파일

디렉토리 `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`에는 **다른 파일 확장자와 관련된 위험에 대한 정보**가 저장됩니다. 이 디렉토리는 파일을 다양한 위험 수준으로 분류하여 Safari가 다운로드 후 이러한 파일을 처리하는 방식에 영향을 줍니다. 카테고리는 다음과 같습니다:

* **LSRiskCategorySafe**: 이 카테고리에 속하는 파일은 **완전히 안전**하다고 간주됩니다. Safari는 이러한 파일을 자동으로 다운로드 후 엽니다.
* **LSRiskCategoryNeutral**: 이러한 파일은 경고가 없으며 Safari에 의해 **자동으로 열리지 않습니다**.
* **LSRiskCategoryUnsafeExecutable**: 이 카테고리의 파일은 응용 프로그램임을 나타내는 경고를 **발생**시킵니다. 이는 사용자에게 경고하는 보안 조치로 작용합니다.
* **LSRiskCategoryMayContainUnsafeExecutable**: 이 카테고리는 압축 파일과 같이 실행 파일을 포함할 수 있는 파일에 대한 것입니다. Safari는 모든 내용이 안전하거나 중립적임을 확인할 수 없는 한 **경고**를 발생시킵니다.

## 로그 파일

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: 다운로드된 파일에 대한 정보를 포함하며, 다운로드된 URL과 같은 정보가 포함됩니다.
* **`/var/log/system.log`**: OSX 시스템의 주요 로그입니다. com.apple.syslogd.plist은 시스템 로깅의 실행을 담당합니다 (`launchctl list`에서 "com.apple.syslogd"를 찾아 비활성화되었는지 확인할 수 있습니다).
* **`/private/var/log/asl/*.asl`**: Apple 시스템 로그로서 흥미로운 정보를 포함할 수 있습니다.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder"를 통해 최근에 액세스한 파일 및 응용 프로그램을 저장합니다.
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: 시스템 부팅 시 시작할 항목을 저장합니다.
* **`$HOME/Library/Logs/DiskUtility.log`**: DiskUtility 앱에 대한 로그 파일 (USB를 포함한 드라이브에 대한 정보 포함).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: 무선 액세스 포인트에 대한 데이터입니다.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: 비활성화된 데몬 목록입니다.
