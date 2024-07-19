# macOS Gatekeeper / Quarantine / XProtect

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Gatekeeper

**Gatekeeper**는 Mac 운영 체제를 위해 개발된 보안 기능으로, 사용자가 **신뢰할 수 있는 소프트웨어만** 시스템에서 실행하도록 보장합니다. 이는 사용자가 **App Store 외부의 소스**에서 다운로드하고 열려고 시도하는 소프트웨어(앱, 플러그인 또는 설치 패키지 등)를 **검증**함으로써 작동합니다.

Gatekeeper의 핵심 메커니즘은 **검증** 프로세스에 있습니다. 다운로드한 소프트웨어가 **인정된 개발자에 의해 서명되었는지** 확인하여 소프트웨어의 진위를 보장합니다. 또한, 소프트웨어가 **Apple에 의해 노타리제이션**되었는지 확인하여 알려진 악성 콘텐츠가 없고 노타리제이션 이후에 변조되지 않았음을 확인합니다.

또한, Gatekeeper는 사용자가 다운로드한 소프트웨어를 처음 열 때 **승인을 요청**하여 사용자 제어 및 보안을 강화합니다. 이 보호 장치는 사용자가 무심코 해로운 실행 코드를 실행하는 것을 방지하는 데 도움을 줍니다.

### Application Signatures

애플리케이션 서명, 즉 코드 서명은 Apple의 보안 인프라의 중요한 구성 요소입니다. 이는 소프트웨어 저자(개발자)의 **신원을 검증**하고 코드가 마지막으로 서명된 이후에 변조되지 않았음을 보장하는 데 사용됩니다.

작동 방식은 다음과 같습니다:

1. **애플리케이션 서명:** 개발자가 애플리케이션을 배포할 준비가 되면, **개인 키를 사용하여 애플리케이션에 서명**합니다. 이 개인 키는 개발자가 Apple Developer Program에 등록할 때 Apple이 발급하는 **인증서와 연결되어 있습니다**. 서명 프로세스는 앱의 모든 부분에 대한 암호화 해시를 생성하고 이 해시를 개발자의 개인 키로 암호화하는 과정을 포함합니다.
2. **애플리케이션 배포:** 서명된 애플리케이션은 개발자의 인증서와 함께 사용자에게 배포되며, 이 인증서에는 해당 공개 키가 포함되어 있습니다.
3. **애플리케이션 검증:** 사용자가 애플리케이션을 다운로드하고 실행하려고 시도할 때, Mac 운영 체제는 개발자의 인증서에서 공개 키를 사용하여 해시를 복호화합니다. 그런 다음 현재 애플리케이션 상태를 기반으로 해시를 재계산하고 이를 복호화된 해시와 비교합니다. 일치하면 **애플리케이션이 개발자가 서명한 이후로 수정되지 않았음을 의미하며**, 시스템은 애플리케이션 실행을 허용합니다.

애플리케이션 서명은 Apple의 Gatekeeper 기술의 필수적인 부분입니다. 사용자가 **인터넷에서 다운로드한 애플리케이션을 열려고 시도할 때**, Gatekeeper는 애플리케이션 서명을 검증합니다. Apple이 알려진 개발자에게 발급한 인증서로 서명되었고 코드가 변조되지 않았다면, Gatekeeper는 애플리케이션 실행을 허용합니다. 그렇지 않으면 애플리케이션을 차단하고 사용자에게 경고합니다.

macOS Catalina부터는 **Gatekeeper가 애플리케이션이 Apple에 의해 노타리제이션되었는지**도 확인하여 추가 보안 계층을 추가합니다. 노타리제이션 프로세스는 애플리케이션에서 알려진 보안 문제와 악성 코드를 검사하며, 이러한 검사가 통과하면 Apple은 Gatekeeper가 검증할 수 있는 티켓을 애플리케이션에 추가합니다.

#### Check Signatures

일부 **악성 샘플**을 확인할 때는 항상 **서명**을 확인해야 하며, 서명한 **개발자**가 이미 **악성 코드와 관련이 있을 수 있습니다.**
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

Apple의 노타리제이션 프로세스는 사용자를 잠재적으로 해로운 소프트웨어로부터 보호하기 위한 추가적인 안전장치 역할을 합니다. 이는 **개발자가 자신의 애플리케이션을** **Apple의 노타리 서비스**에 제출하여 검토를 받는 과정을 포함합니다. 이 서비스는 App Review와 혼동해서는 안 됩니다. 이 서비스는 **자동화된 시스템**으로, 제출된 소프트웨어에 **악성 콘텐츠**와 코드 서명과 관련된 잠재적인 문제를 검사합니다.

소프트웨어가 우려 사항 없이 이 검사를 **통과**하면, 노타리 서비스는 노타리제이션 티켓을 생성합니다. 개발자는 **이 티켓을 자신의 소프트웨어에 첨부해야** 하며, 이를 '스테이플링'이라고 합니다. 또한, 노타리제이션 티켓은 온라인에 게시되어 Gatekeeper, Apple의 보안 기술이 이를 접근할 수 있습니다.

사용자가 소프트웨어를 처음 설치하거나 실행할 때, 노타리제이션 티켓의 존재 - 실행 파일에 스테이플링되었거나 온라인에서 발견된 경우 - **Gatekeeper에 소프트웨어가 Apple에 의해 노타리제이션되었음을 알립니다**. 결과적으로, Gatekeeper는 초기 실행 대화 상자에 설명 메시지를 표시하여 소프트웨어가 Apple에 의해 악성 콘텐츠 검사를 받았음을 나타냅니다. 이 과정은 사용자가 자신의 시스템에 설치하거나 실행하는 소프트웨어의 보안에 대한 신뢰를 높입니다.

### Enumerating GateKeeper

GateKeeper는 신뢰할 수 없는 앱의 실행을 방지하는 **여러 보안 구성 요소**이자 **구성 요소 중 하나**입니다.

GateKeeper의 **상태**를 확인하는 것은 가능합니다:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
GateKeeper 서명 검사는 **격리 속성**이 있는 파일에 대해서만 수행되며, 모든 파일에 대해 수행되지 않습니다.
{% endhint %}

GateKeeper는 **설정 및 서명**에 따라 이진 파일이 실행될 수 있는지 확인합니다:

<figure><img src="../../../.gitbook/assets/image (1150).png" alt=""><figcaption></figcaption></figure>

이 구성을 유지하는 데이터베이스는 **`/var/db/SystemPolicy`**에 위치합니다. 루트로 이 데이터베이스를 확인할 수 있습니다:
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
Note how the first rule ended in "**App Store**" and the second one in "**Developer ID**" and that in the previous imaged it was **enabled to execute apps from the App Store and identified developers**.\
If you **modify** that setting to App Store, the "**Notarized Developer ID" rules will disappear**.

There are also thousands of rules of **type GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
이 해시는 **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** 및 **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**에서 가져온 것입니다.

또는 이전 정보를 다음과 같이 나열할 수 있습니다:
```bash
sudo spctl --list
```
The options **`--master-disable`** and **`--global-disable`** of **`spctl`** will completely **disable** these signature checks:  
옵션 **`--master-disable`** 및 **`--global-disable`**는 **`spctl`**의 서명 검사를 완전히 **비활성화**합니다:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
완전히 활성화되면 새로운 옵션이 나타납니다:

<figure><img src="../../../.gitbook/assets/image (1151).png" alt=""><figcaption></figcaption></figure>

**앱이 GateKeeper에 의해 허용될지 확인할 수 있습니다**:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper에 특정 앱의 실행을 허용하는 새로운 규칙을 추가하는 것이 가능합니다:
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
### Quarantine Files

응용 프로그램이나 파일을 **다운로드**할 때, 웹 브라우저나 이메일 클라이언트와 같은 특정 macOS **응용 프로그램**은 다운로드된 파일에 일반적으로 "**격리 플래그**"로 알려진 **확장 파일 속성**을 **첨부**합니다. 이 속성은 파일이 신뢰할 수 없는 출처(인터넷)에서 왔음을 **표시**하는 보안 조치로 작용하며, 잠재적인 위험을 내포할 수 있습니다. 그러나 모든 응용 프로그램이 이 속성을 첨부하는 것은 아니며, 예를 들어 일반적인 BitTorrent 클라이언트 소프트웨어는 보통 이 과정을 우회합니다.

**격리 플래그의 존재는 사용자가 파일을 실행하려고 할 때 macOS의 Gatekeeper 보안 기능에 신호를 보냅니다.**

**격리 플래그가 존재하지 않는 경우**(일부 BitTorrent 클라이언트를 통해 다운로드된 파일과 같이), Gatekeeper의 **검사가 수행되지 않을 수 있습니다**. 따라서 사용자는 덜 안전하거나 알려지지 않은 출처에서 다운로드한 파일을 열 때 주의해야 합니다.

{% hint style="info" %}
**코드 서명의 유효성**을 **확인하는** 것은 코드와 모든 번들 리소스의 암호화된 **해시**를 생성하는 **자원 집약적인** 과정입니다. 또한, 인증서 유효성을 확인하는 것은 발급 후 취소되었는지 확인하기 위해 Apple의 서버에 **온라인 확인**을 수행하는 것을 포함합니다. 이러한 이유로, 앱이 실행될 때마다 전체 코드 서명 및 인증 확인을 **실행하는 것은 비현실적입니다**.

따라서 이러한 검사는 **격리 속성이 있는 앱을 실행할 때만 수행됩니다.**
{% endhint %}

{% hint style="warning" %}
이 속성은 **파일을 생성/다운로드하는 응용 프로그램에 의해 설정되어야 합니다.**

그러나 샌드박스된 파일은 생성하는 모든 파일에 이 속성이 설정됩니다. 비샌드박스 앱은 스스로 설정할 수 있거나, 시스템이 생성된 파일에 `com.apple.quarantine` 확장 속성을 설정하도록 **Info.plist**에서 [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) 키를 지정할 수 있습니다.
{% endhint %}

또한, **`qtn_proc_apply_to_self`**를 호출하는 프로세스에 의해 생성된 모든 파일은 격리됩니다. 또는 API **`qtn_file_apply_to_path`**는 지정된 파일 경로에 격리 속성을 추가합니다.

상태를 **확인하고 활성화/비활성화**(루트 필요)하는 것이 가능합니다:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
You can also **find if a file has the quarantine extended attribute** with:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
확인하십시오 **값** **확장된** **속성** 및 다음과 같이 격리 속성을 작성한 앱을 찾으십시오:
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
실제로 프로세스는 "생성한 파일에 격리 플래그를 설정할 수 있습니다" (생성한 파일에 USER_APPROVED 플래그를 적용하려고 했지만 적용되지 않았습니다):

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

그리고 **제거**하려면 다음 속성을 사용하세요:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
모든 격리된 파일을 찾으려면:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

격리 정보는 **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**에 있는 LaunchServices에 의해 관리되는 중앙 데이터베이스에 저장됩니다.

#### **Quarantine.kext**

커널 확장은 **시스템의 커널 캐시**를 통해서만 사용할 수 있습니다. 그러나 **Kernel Debug Kit를 https://developer.apple.com/**에서 다운로드할 수 있으며, 여기에는 확장의 기호화된 버전이 포함되어 있습니다.

### XProtect

XProtect는 macOS에 내장된 **안티멀웨어** 기능입니다. XProtect는 **응용 프로그램이 처음 실행되거나 수정될 때 알려진 맬웨어 및 안전하지 않은 파일 유형의 데이터베이스와 비교하여 검사합니다**. Safari, Mail 또는 Messages와 같은 특정 앱을 통해 파일을 다운로드하면 XProtect가 자동으로 파일을 스캔합니다. 파일이 데이터베이스의 알려진 맬웨어와 일치하면 XProtect는 **파일 실행을 차단하고 위협에 대해 경고합니다**.

XProtect 데이터베이스는 **Apple에 의해 정기적으로** 새로운 맬웨어 정의로 업데이트되며, 이러한 업데이트는 자동으로 다운로드되어 Mac에 설치됩니다. 이를 통해 XProtect는 항상 최신 알려진 위협에 대해 최신 상태를 유지합니다.

그러나 **XProtect는 완전한 기능을 갖춘 안티바이러스 솔루션이 아닙니다**. 특정 알려진 위협 목록만 검사하며 대부분의 안티바이러스 소프트웨어처럼 접근 시 스캔을 수행하지 않습니다.

최신 XProtect 업데이트에 대한 정보를 얻으려면: 

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect는 **/Library/Apple/System/Library/CoreServices/XProtect.bundle**에 위치하며, 번들 안에는 XProtect가 사용하는 정보가 있습니다:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: 해당 cdhashes를 가진 코드가 레거시 권한을 사용할 수 있도록 허용합니다.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID 및 TeamID를 통해 로드가 금지된 플러그인 및 확장 목록 또는 최소 버전을 나타냅니다.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: 맬웨어를 탐지하기 위한 Yara 규칙입니다.
* **`XProtect.bundle/Contents/Resources/gk.db`**: 차단된 애플리케이션 및 TeamID의 해시가 포함된 SQLite3 데이터베이스입니다.

**`/Library/Apple/System/Library/CoreServices/XProtect.app`**에 XProtect와 관련된 또 다른 앱이 있지만, Gatekeeper 프로세스와는 관련이 없습니다.

### Gatekeeper가 아님

{% hint style="danger" %}
Gatekeeper는 애플리케이션을 실행할 때마다 **실행되지 않습니다**. 오직 _**AppleMobileFileIntegrity**_ (AMFI)만이 Gatekeeper에 의해 이미 실행되고 검증된 앱을 실행할 때 **실행 가능한 코드 서명을 검증**합니다.
{% endhint %}

따라서 이전에는 앱을 실행하여 Gatekeeper로 캐시한 후, **애플리케이션의 실행 불가능한 파일**(예: Electron asar 또는 NIB 파일)을 수정하고, 다른 보호 장치가 없다면 애플리케이션이 **악성** 추가 사항과 함께 **실행되었습니다**.

하지만 이제는 macOS가 애플리케이션 번들 내 파일 수정을 **방지하기 때문에** 이 방법은 더 이상 불가능합니다. 따라서 [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) 공격을 시도하면, 앱을 실행하여 Gatekeeper로 캐시한 후 번들을 수정할 수 없기 때문에 더 이상 악용할 수 없음을 알게 될 것입니다. 예를 들어 Contents 디렉토리의 이름을 NotCon으로 변경하고(익스플로잇에 명시된 대로) 앱의 주요 바이너리를 실행하여 Gatekeeper로 캐시하면 오류가 발생하고 실행되지 않습니다.

## Gatekeeper 우회

Gatekeeper를 우회하는 방법(사용자가 무언가를 다운로드하고 Gatekeeper가 이를 차단해야 할 때 실행하도록 만드는 것)은 macOS의 취약점으로 간주됩니다. 과거에 Gatekeeper를 우회할 수 있게 해준 기술에 할당된 CVE는 다음과 같습니다:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility**를 사용하여 추출할 경우, **경로가 886자를 초과하는** 파일은 com.apple.quarantine 확장 속성을 받지 않는 것으로 관찰되었습니다. 이 상황은 의도치 않게 해당 파일이 **Gatekeeper의** 보안 검사를 **우회**할 수 있게 합니다.

자세한 내용은 [**원본 보고서**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)를 확인하세요.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator**로 생성된 애플리케이션의 경우, 실행에 필요한 정보는 `application.app/Contents/document.wflow`에 있으며 실행 파일에는 없습니다. 실행 파일은 **Automator Application Stub**이라는 일반 Automator 바이너리입니다.

따라서 `application.app/Contents/MacOS/Automator\ Application\ Stub`이 **시스템 내 다른 Automator Application Stub을 가리키는 심볼릭 링크로 설정**할 수 있으며, 그러면 `document.wflow`(당신의 스크립트) **를 실행하되 Gatekeeper를 트리거하지 않습니다**. 실제 실행 파일에는 격리 xattr가 없기 때문입니다.

예상 위치: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

자세한 내용은 [**원본 보고서**](https://ronmasas.com/posts/bypass-macos-gatekeeper)를 확인하세요.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

이 우회에서는 `application.app/Contents`에서 압축을 시작하는 애플리케이션으로 zip 파일이 생성되었습니다. 따라서 **quarantine attr**는 **`application.app/Contents`의 모든 파일에 적용되었지만**, **`application.app`에는 적용되지 않았습니다**. Gatekeeper가 확인하는 것은 `application.app`이기 때문에, Gatekeeper는 우회되었습니다. `application.app`이 트리거될 때 **quarantine 속성이 없었습니다.**
```bash
zip -r test.app/Contents test.zip
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) for more information.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

구성 요소가 다르더라도 이 취약점의 악용은 이전 것과 매우 유사합니다. 이 경우 **`application.app/Contents`**에서 Apple Archive를 생성하여 **`application.app`**이 **Archive Utility**에 의해 압축 해제될 때 격리 속성을 받지 않도록 합니다.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) for more information.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**는 파일에 속성을 쓰는 것을 방지하는 데 사용할 수 있습니다:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Moreover, **AppleDouble** 파일 형식은 ACE를 포함하여 파일을 복사합니다.

[**소스 코드**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)에서 **`com.apple.acl.text`**라는 xattr에 저장된 ACL 텍스트 표현이 압축 해제된 파일의 ACL로 설정될 것임을 확인할 수 있습니다. 따라서 ACL이 다른 xattrs가 작성되는 것을 방지하는 애플리케이션을 **AppleDouble** 파일 형식으로 zip 파일로 압축했다면... 격리 xattr는 애플리케이션에 설정되지 않았습니다:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

자세한 정보는 [**원본 보고서**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)를 확인하세요.

이것은 AppleArchives로도 악용될 수 있습니다:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

**구글 크롬이 다운로드된 파일에 격리 속성을 설정하지 않는** 문제가 macOS 내부 문제로 발견되었습니다.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble 파일 형식은 `._`로 시작하는 별도의 파일에 파일의 속성을 저장하며, 이는 **macOS 기계 간에 파일 속성을 복사하는 데 도움을 줍니다**. 그러나 AppleDouble 파일을 압축 해제한 후 `._`로 시작하는 파일이 **격리 속성을 부여받지 않는** 것으로 나타났습니다.

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

파일을 생성할 수 있는 것은 **Gatekeeper를 우회할 수 있었습니다.** 이 요령은 **AppleDouble 이름 규칙**을 사용하여 **DMG 파일 애플리케이션**을 생성하고, **이 숨겨진** 파일에 대한 심볼릭 링크로 **보이는 파일을 생성하는** 것이었습니다.\
**dmg 파일이 실행될 때**, 쿼런틴 속성이 없기 때문에 **Gatekeeper를 우회하게 됩니다.**
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

* 앱이 포함된 디렉토리를 생성합니다.
* 앱에 uchg를 추가합니다.
* 앱을 tar.gz 파일로 압축합니다.
* tar.gz 파일을 피해자에게 보냅니다.
* 피해자가 tar.gz 파일을 열고 앱을 실행합니다.
* Gatekeeper는 앱을 확인하지 않습니다.

### Prevent Quarantine xattr

".app" 번들에 격리 xattr가 추가되지 않으면, 실행할 때 **Gatekeeper가 트리거되지 않습니다**.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
