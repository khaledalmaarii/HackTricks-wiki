# macOS 파일, 폴더, 이진 파일 및 메모리

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 파일 계층 구조 레이아웃

* **/Applications**: 설치된 앱은 여기에 있어야 합니다. 모든 사용자가 액세스할 수 있습니다.
* **/bin**: 명령 줄 이진 파일
* **/cores**: 존재하는 경우, 코어 덤프를 저장하는 데 사용됩니다.
* **/dev**: 모든 것이 파일로 처리되므로 하드웨어 장치가 여기에 저장될 수 있습니다.
* **/etc**: 구성 파일
* **/Library**: 환경 설정, 캐시 및 로그와 관련된 많은 하위 디렉터리와 파일이 여기에 있을 수 있습니다. 루트 및 각 사용자 디렉터리에 Library 폴더가 있습니다.
* **/private**: 문서화되지 않았지만, 언급된 많은 폴더는 private 디렉터리로의 심볼릭 링크입니다.
* **/sbin**: 핵심 시스템 이진 파일 (관리와 관련됨)
* **/System**: OS X를 실행하기 위한 파일입니다. 주로 Apple 특정 파일만 여기에서 찾을 수 있습니다 (타사 파일은 아님).
* **/tmp**: 파일은 3일 후에 삭제됩니다 (/private/tmp로의 소프트 링크입니다).
* **/Users**: 사용자의 홈 디렉터리입니다.
* **/usr**: 구성 및 시스템 이진 파일
* **/var**: 로그 파일
* **/Volumes**: 마운트된 드라이브가 여기에 나타납니다.
* **/.vol**: `stat a.txt`를 실행하면 `16777223 7545753 -rw-r--r-- 1 username wheel ...`와 같은 결과를 얻을 수 있습니다. 여기서 첫 번째 숫자는 파일이 존재하는 볼륨의 ID 번호이고 두 번째 숫자는 inode 번호입니다. 이 정보를 사용하여 /.vol/에서 이 파일의 내용에 액세스할 수 있습니다. `cat /.vol/16777223/7545753`을 실행하세요.

### 애플리케이션 폴더

* **시스템 애플리케이션**은 `/System/Applications`에 위치합니다.
* **설치된** 애플리케이션은 일반적으로 `/Applications` 또는 `~/Applications`에 설치됩니다.
* **애플리케이션 데이터**는 루트로 실행되는 애플리케이션의 경우 `/Library/Application Support`에, 사용자로 실행되는 애플리케이션의 경우 `~/Library/Application Support`에 있을 수 있습니다.
* **루트로 실행되어야 하는** 타사 애플리케이션 **데몬**은 일반적으로 `/Library/PrivilegedHelperTools/`에 위치합니다.
* **샌드박스** 앱은 `~/Library/Containers` 폴더에 매핑됩니다. 각 앱은 애플리케이션의 번들 ID (`com.apple.Safari`)에 따라 이름이 지정된 폴더를 가지고 있습니다.
* **커널**은 `/System/Library/Kernels/kernel`에 위치합니다.
* **Apple의 커널 확장**은 `/System/Library/Extensions`에 위치합니다.
* **타사 커널 확장**은 `/Library/Extensions`에 저장됩니다.

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
* **`.kext`**: 특정 구조를 따라야 하며, OS X 버전의 드라이버입니다. (번들입니다)
* **`.plist`**: 속성 목록으로 알려진 파일은 XML 또는 이진 형식으로 정보를 저장합니다.
* XML 또는 이진 형식일 수 있습니다. 이진 파일은 다음과 같이 읽을 수 있습니다:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: 디렉터리 구조를 따르는 Apple 애플리케이션입니다 (번들입니다).
* **`.dylib`**: 동적 라이브러리 (Windows DLL 파일과 유사)
* **`.pkg`**: xar (eXtensible Archive 형식)와 동일합니다. installer 명령을 사용하여 이러한 파일의 내용을 설치할 수 있습니다.
* **`.DS_Store`**: 이 파일은 각 디렉터리에 있으며, 디렉터리의 속성과 사용자 정의를 저장합니다.
* **`.Spotlight-V100`**: 이 폴더는 시스템의 모든 볼륨의 루트 디렉터리에 나타납니다.
* **`.metadata_never_index`**: 이 파일이 볼륨의 루트에 있으면 Spotlight는 해당 볼륨을 색인화하지 않습니다.
* **`.noindex`**: 이 확장자를 가진 파일과 폴더는 Spotlight에 의해 색인화되지 않습니다.

### macOS 번들

번들은 Finder에서 객체처럼 보이는 **디렉터리**입니다 (번들 예시는 `*.app` 파일입니다).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld 공유 캐시

macOS (및 iOS)에서 모든 시스템 공유 라이브러리 (프레임워크 및 dylib과 같은)는 **단일 파일**인 **dyld 공유 캐시**에 **결합**됩니다. 이렇게 하면 코드를 더 빠르게 로드할 수 있어 성능이 향상됩니다.

dyld 공유 캐시와 유사하게, 커널과 커널 확장도 부팅 시간에 로드되는 커널 캐시로 컴파일됩니다.

단일 파일 dylib 공유 캐시에서 라이브러리를 추출하기 위해 이전에는 이진 파일 [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip)을 사용할 수 있었지만, 현재는 작동하지 않을 수도 있습니다. 대신 [**dyldextractor**](https://github.com/arandomdev/dyldextractor)를 사용할 수도 있습니다:

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

이전 버전에서는 **`/System/Library/dyld/`**에서 **공유 캐시**를 찾을 수 있을 수도 있습니다.

iOS에서는 **`/System/Library/Caches/com.apple.dyld/`**에서 찾을 수 있습니다.

{% hint style="success" %}
`dyld_shared_cache_util` 도구가 작동하지 않더라도, **공유 dyld 바이너리를 Hopper에 전달**하면 Hopper가 모든 라이브러리를 식별하고 **조사할 라이브러리를 선택**할 수 있습니다:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## 특수 파일 권한

### 폴더 권한

**폴더**에서 **읽기**는 **목록을 보는 것**을 허용하고, **쓰기**는 **파일을 삭제하고 쓰는 것**을 허용하며, **실행**은 **디렉토리를 탐색하는 것**을 허용합니다. 예를 들어, **폴더 내의 파일에 대해 읽기 권한**을 가진 사용자는 **실행 권한이 없는 디렉토리**에서는 파일을 **읽을 수 없습니다**.

### 플래그 수정자

파일에 설정된 일부 플래그는 파일의 동작을 다르게 만들 수 있습니다. `ls -lO /path/directory` 명령을 사용하여 디렉토리 내의 파일의 플래그를 **확인**할 수 있습니다.

* **`uchg`**: **uchange** 플래그라고도 알려져 있으며, **파일을 변경하거나 삭제하는 모든 작업을 방지**합니다. 이를 설정하려면 `chflags uchg file.txt`를 사용합니다.
* root 사용자는 **플래그를 제거**하고 파일을 수정할 수 있습니다.
* **`restricted`**: 이 플래그는 파일이 **SIP로 보호**되도록 만듭니다(이 플래그를 파일에 추가할 수 없음).
* **`Sticky bit`**: Sticky bit가 있는 디렉토리의 경우, **디렉토리 소유자 또는 root만 파일 이름을 변경하거나 삭제**할 수 있습니다. 일반적으로 이는 /tmp 디렉토리에 설정되어 일반 사용자가 다른 사용자의 파일을 삭제하거나 이동하지 못하도록 합니다.

### **파일 ACLs**

파일 **ACLs**에는 다른 사용자에게 **더 세분화된 권한**을 할당할 수 있는 **ACE** (Access Control Entries)가 포함됩니다.

**디렉토리**에는 다음과 같은 권한을 부여할 수 있습니다: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
**파일**에는 다음과 같은 권한을 부여할 수 있습니다: `read`, `write`, `append`, `execute`.

파일에 ACL이 포함되어 있는 경우, 권한을 나열할 때 **"+"가 표시**됩니다.
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
다음 명령을 사용하여 파일의 **ACL(액세스 제어 목록)**을 읽을 수 있습니다:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
**모든 ACL이 있는 파일을 찾을 수 있습니다** (이 작업은 아주 느립니다):

```bash
find / -type f -exec ls -le {} \; 2>/dev/null
```

**Note**: This command may take a long time to complete.
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### 리소스 포크 | macOS ADS

이것은 MacOS 기기에서 **대체 데이터 스트림(Alternate Data Streams)**을 얻는 방법입니다. 파일을 **file/..namedfork/rsrc**에 저장하여 **com.apple.ResourceFork**라는 확장 속성 내에 내용을 저장할 수 있습니다.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
다음 명령어를 사용하여 **이 확장 속성을 포함하는 모든 파일을 찾을 수 있습니다**:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Universal binaries &** Mach-o Format

맥 OS 바이너리는 일반적으로 **유니버설 바이너리**로 컴파일됩니다. **유니버설 바이너리**는 **동일한 파일에서 여러 아키텍처를 지원**할 수 있습니다.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS 메모리 덤프

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Mac OS의 위험 범주 파일

디렉토리 `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`에는 **다른 파일 확장자와 관련된 위험에 대한 정보가 저장**됩니다. 이 디렉토리는 파일을 다양한 위험 수준으로 분류하여 Safari가 다운로드 후 이러한 파일을 처리하는 방식에 영향을 줍니다. 카테고리는 다음과 같습니다:

- **LSRiskCategorySafe**: 이 카테고리의 파일은 **완전히 안전**하다고 간주됩니다. Safari는 이러한 파일을 자동으로 다운로드 후 엽니다.
- **LSRiskCategoryNeutral**: 이러한 파일은 경고 없이 제공되며 Safari에서 **자동으로 열리지 않습니다**.
- **LSRiskCategoryUnsafeExecutable**: 이 카테고리의 파일은 응용 프로그램임을 나타내는 경고를 **트리거**합니다. 이는 사용자에게 경고를 알리는 보안 조치로 작동합니다.
- **LSRiskCategoryMayContainUnsafeExecutable**: 이 카테고리는 아카이브와 같은 파일에 포함될 수 있는 실행 파일과 같은 파일을 위한 것입니다. Safari는 모든 내용이 안전하거나 중립적임을 확인할 수 없는 경우 **경고를 트리거**합니다.

## 로그 파일

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: 다운로드된 파일에 대한 정보를 포함하고 있으며, 다운로드된 URL도 포함합니다.
* **`/var/log/system.log`**: OSX 시스템의 주 로그입니다. syslogging의 실행을 담당하는 com.apple.syslogd.plist 파일입니다 (`launchctl list`에서 "com.apple.syslogd"를 찾아 비활성화되었는지 확인할 수 있습니다).
* **`/private/var/log/asl/*.asl`**: 이는 흥미로운 정보를 포함할 수 있는 Apple 시스템 로그입니다.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder"를 통해 최근에 액세스한 파일 및 애플리케이션을 저장합니다.
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: 시스템 시작 시 실행할 항목을 저장합니다.
* **`$HOME/Library/Logs/DiskUtility.log`**: DiskUtility 앱에 대한 로그 파일입니다(USB를 포함한 드라이브에 대한 정보 포함).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: 무선 액세스 포인트에 대한 데이터입니다.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: 비활성화된 데몬 목록입니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
