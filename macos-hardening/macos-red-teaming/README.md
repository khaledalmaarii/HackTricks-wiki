# macOS Red Teaming

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

## MDM 남용

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

관리 플랫폼에 액세스하기 위해 **관리자 자격 증명을 침해**하면 악성 코드를 컴퓨터에 배포하여 **모든 컴퓨터를 잠재적으로 침해**할 수 있습니다.

MacOS 환경에서 레드 팀 활동을 위해서는 MDM의 작동 방식에 대한 이해가 매우 권장됩니다:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### MDM을 C2로 사용하기

MDM은 프로필을 설치, 쿼리 또는 제거하고 애플리케이션을 설치하고 로컬 관리자 계정을 생성하고 펌웨어 암호를 설정하고 FileVault 키를 변경하는 권한이 있습니다.

자체 MDM을 실행하려면 [**https://mdmcert.download/**](https://mdmcert.download/)에서 **공급업체에 의해 서명된 CSR**을 얻으려고 시도할 수 있습니다. Apple 기기용 자체 MDM을 실행하려면 [**MicroMDM**](https://github.com/micromdm/micromdm)을 사용할 수 있습니다.

그러나 등록된 기기에 애플리케이션을 설치하려면 여전히 개발자 계정으로 서명해야 합니다... 그러나 MDM 등록 시 **기기는 신뢰할 수 있는 CA로 MDM의 SSL 인증서를 추가**하므로 이제 모든 것을 서명할 수 있습니다.

기기를 MDM에 등록하려면 루트로 **`mobileconfig`** 파일을 설치해야 합니다. 이 파일은 **pkg** 파일을 통해 전달될 수 있습니다 (zip으로 압축하고 Safari에서 다운로드하면 압축이 풀립니다).

**Mythic agent Orthrus**는 이 기술을 사용합니다.

### JAMF PRO 남용

JAMF는 **사용자 지정 스크립트** (시스템 관리자가 개발한 스크립트), **네이티브 페이로드** (로컬 계정 생성, EFI 암호 설정, 파일/프로세스 모니터링...) 및 **MDM** (기기 구성, 기기 인증서...)를 실행할 수 있습니다.

#### JAMF 자체 등록

`https://<company-name>.jamfcloud.com/enroll/`과 같은 페이지로 이동하여 **자체 등록이 활성화**되어 있는지 확인하세요. 활성화되어 있다면 **액세스하기 위한 자격 증명을 요청**할 수 있습니다.

[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) 스크립트를 사용하여 패스워드 스프레이 공격을 수행할 수 있습니다.

또한 적절한 자격 증명을 찾은 후 다음 양식으로 다른 사용자 이름을 브루트 포스할 수 있습니다:

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### JAMF 기기 인증

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**`jamf`** 바이너리에는 열쇠 체인을 열기 위한 비밀이 포함되어 있었으며, 발견 당시에는 모두와 **공유**되었으며, 비밀은 **`jk23ucnq91jfu9aj`**였습니다.\
또한 jamf는 **LaunchDaemon**으로 **`/Library/LaunchAgents/com.jamf.management.agent.plist`**에 **지속**됩니다.

#### JAMF 기기 탈취

**`jamf`**가 사용할 **JSS** (Jamf Software Server) **URL**은 **`/Library/Preferences/com.jamfsoftware.jamf.plist`**에 위치합니다.\
이 파일에는 기본적으로 URL이 포함되어 있습니다:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

따라서, 공격자는 악성 패키지 (`pkg`)를 드롭할 수 있으며, 이 패키지는 설치될 때 **이 파일을 덮어쓰고 URL을 Typhon 에이전트의 Mythic C2 수신기로 설정**하여 JAMF를 C2로 남용할 수 있게 됩니다.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF 위장

장치와 JMF 간의 통신을 위해 **통신을 위장**하기 위해서는 다음이 필요합니다:

* 장치의 **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* 장치 인증서를 포함하는 **JAMF 키체인** 위치: `/Library/Application\ Support/Jamf/JAMF.keychain`

이 정보를 사용하여 **훔친** 하드웨어 **UUID**와 **SIP 비활성화**가 적용된 **JAMF 키체인**을 가진 **가상 머신**을 생성하고, Jamf **에이전트**를 **감시**하고 정보를 훔칠 수 있습니다.

#### 비밀 정보 훔치기

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

또한, 관리자가 Jamf를 통해 실행하려는 **사용자 정의 스크립트**를 모니터링하기 위해 위치 `/Library/Application Support/Jamf/tmp/`를 모니터링할 수 있습니다. 이 스크립트에는 **자격 증명**이 포함될 수 있습니다.

그러나, **자격 증명**은 **매개 변수**로 이러한 스크립트를 통해 전달될 수 있으므로 `ps aux | grep -i jamf`를 모니터링해야 합니다(루트 권한이 없어도 됩니다).

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) 스크립트는 새로운 파일이 추가되고 새로운 프로세스 인수가 추가될 때까지 대기할 수 있습니다.

### macOS 원격 접속

또한 **MacOS**의 "특별한" **네트워크** **프로토콜**에 대해서도 알아보세요:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

일부 경우에는 **MacOS 컴퓨터가 AD에 연결**되어 있는 것을 발견할 수 있습니다. 이 경우에는 일반적으로 알고 있는 대로 active directory를 **열거**해보는 것이 좋습니다. 다음 페이지에서 도움을 얻을 수 있습니다:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

일부 **로컬 MacOS 도구**인 `dscl`도 도움이 될 수 있습니다.
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
또한, MacOS에서 AD를 자동으로 열거하고 kerberos와 상호 작용하는 도구들이 준비되어 있습니다:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound는 Bloodhound 감사 도구의 확장으로, MacOS 호스트에서 Active Directory 관계를 수집하고 흡수할 수 있도록 해줍니다.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost는 macOS에서 Heimdal krb5 API와 상호 작용하기 위해 설계된 Objective-C 프로젝트입니다. 이 프로젝트의 목표는 대상 시스템에 다른 프레임워크나 패키지 없이도 네이티브 API를 사용하여 macOS 장치에서 Kerberos에 대한 보안 테스트를 더욱 용이하게 하는 것입니다.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory 열거를 수행하기 위한 JavaScript for Automation (JXA) 도구입니다.

### 도메인 정보
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### 사용자

MacOS의 세 가지 유형의 사용자는 다음과 같습니다:

* **로컬 사용자** - 로컬 OpenDirectory 서비스에서 관리되며 Active Directory와 어떤 방식으로도 연결되어 있지 않습니다.
* **네트워크 사용자** - DC 서버에 인증하기 위해 연결이 필요한 휘발성 Active Directory 사용자입니다.
* **모바일 사용자** - 자격 증명 및 파일에 대한 로컬 백업이 있는 Active Directory 사용자입니다.

사용자 및 그룹에 대한 로컬 정보는 _/var/db/dslocal/nodes/Default_ 폴더에 저장됩니다.\
예를 들어, _mark_라는 사용자에 대한 정보는 _/var/db/dslocal/nodes/Default/users/mark.plist_에 저장되며, _admin_ 그룹에 대한 정보는 _/var/db/dslocal/nodes/Default/groups/admin.plist_에 저장됩니다.

MacHound는 Bloodhound 데이터베이스에 HasSession 및 AdminTo 엣지 외에도 **세 가지 새로운 엣지**를 추가합니다:

* **CanSSH** - 호스트로 SSH 연결을 허용하는 엔티티
* **CanVNC** - 호스트로 VNC 연결을 허용하는 엔티티
* **CanAE** - 호스트에서 AppleEvent 스크립트를 실행할 수 있는 엔티티
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
더 많은 정보는 [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)에서 확인할 수 있습니다.

## 키체인에 접근하기

키체인에는 암호를 생성하지 않고 접근할 경우에도 도움이 될 수 있는 민감한 정보가 많이 포함되어 있습니다. 이는 레드팀 연습을 진행하는 데 도움이 될 수 있습니다:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## 외부 서비스

일반적인 Windows 레드팀과는 달리 MacOS 레드팀은 일반적으로 **MacOS가 직접 여러 외부 플랫폼과 통합**되어 있습니다. MacOS의 일반적인 구성은 **OneLogin 동기화 자격증명을 사용하여 컴퓨터에 액세스하고 OneLogin을 통해 여러 외부 서비스**(예: github, aws...)에 액세스하는 것입니다.

## 기타 레드팀 기술

### Safari

Safari에서 파일을 다운로드하면 "안전한" 파일인 경우 **자동으로 열립니다**. 예를 들어, **zip 파일을 다운로드**하면 자동으로 압축이 해제됩니다:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## 참고 자료

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
