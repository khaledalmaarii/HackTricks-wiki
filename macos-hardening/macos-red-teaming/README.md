# macOS Red Teaming

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 제로에서 영웅까지 AWS 해킹 배우기</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* 여러분의 해킹 기술을 공유하려면 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## MDM 남용

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

관리 플랫폼에 액세스하기 위해 **관리자 자격 증명을 침해**하면 기기에 악성 코드를 배포하여 모든 컴퓨터를 **잠재적으로 침해**할 수 있습니다.

MacOS 환경에서 레드팀 활동을 위해 MDM이 어떻게 작동하는지 이해하는 것이 매우 권장됩니다:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### MDM을 C2로 사용

MDM은 프로필을 설치, 쿼리 또는 제거하거나 애플리케이션을 설치하고 로컬 관리자 계정을 만들고 펌웨어 암호를 설정하고 FileVault 키를 변경하는 권한이 있습니다.

자체 MDM을 실행하려면 [**https://mdmcert.download/**](https://mdmcert.download/)에서 시도할 수 있는 **공급업체에 의해 서명된 CSR**이 필요합니다. 그리고 Apple 기기용 자체 MDM을 실행하려면 [**MicroMDM**](https://github.com/micromdm/micromdm)을 사용할 수 있습니다.

그러나 등록된 기기에 애플리케이션을 설치하려면 여전히 개발자 계정으로 서명해야 합니다... 그러나 MDM 등록 시 **기기는 MDM의 SSL 인증서를 신뢰하는 CA로 추가**되므로 이제 모든 것을 서명할 수 있습니다.

MDM에 기기를 등록하려면 루트로 **`mobileconfig`** 파일을 설치해야 하며, 이 파일은 **pkg** 파일을 통해 전달될 수 있습니다 (Safari에서 다운로드하면 압축이 풀립니다).

**Mythic 에이전트 Orthrus**는 이 기술을 사용합니다.

### JAMF PRO 남용

JAMF는 **사용자 지정 스크립트** (시스템 관리자가 개발한 스크립트), **네이티브 페이로드** (로컬 계정 생성, EFI 암호 설정, 파일/프로세스 모니터링...) 및 **MDM** (기기 구성, 기기 인증서...)를 실행할 수 있습니다.

#### JAMF 자가 등록

`https://<company-name>.jamfcloud.com/enroll/`과 같은 페이지로 이동하여 **자가 등록이 활성화되어 있는지 확인**하세요. 활성화되어 있다면 **액세스 자격 증명을 요청**할 수 있습니다.

[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) 스크립트를 사용하여 패스워드 스프레이 공격을 수행할 수 있습니다.

또한 적절한 자격 증명을 찾은 후 다음 양식으로 다른 사용자 이름을 브루트 포스할 수 있습니다:

![](<../../.gitbook/assets/image (107).png>)

#### JAMF 기기 인증

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** 바이너리에는 열쇠고리를 열기 위한 비밀이 포함되어 있었으며, 발견 당시에는 **모두에게 공유**되었으며: **`jk23ucnq91jfu9aj`**입니다.\
또한 jamf는 **`/Library/LaunchAgents/com.jamf.management.agent.plist`**에 **LaunchDaemon**으로 **지속**됩니다.

#### JAMF 기기 탈취

**`jamf`**가 사용할 **JSS** (Jamf Software Server) **URL**은 **`/Library/Preferences/com.jamfsoftware.jamf.plist`**에 있습니다.\
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

따라서 공격자는 악성 패키지 (`pkg`)를 드롭할 수 있으며, 이 패키지는 설치될 때 **이 파일을 덮어쓰도록** 설정하여 **Typhon 에이전트의 Mythic C2 수신기 URL**로 변경함으로써 JAMF를 C2로 남용할 수 있게 됩니다.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Impersonation

**장치와 JMF 간의 통신을 위장**하기 위해 다음이 필요합니다:

* 장치의 **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* **JAMF 키체인**: `/Library/Application\ Support/Jamf/JAMF.keychain`에서 장치 인증서를 포함

이 정보를 사용하여 **도난당한** 하드웨어 **UUID**로 VM을 만들고 **SIP를 비활성화**하고, **JAMF 키체인을 드롭**하고, Jamf **에이전트를 후킹**하여 정보를 도난할 수 있습니다.

#### 비밀 정보 도난

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

또한 `/Library/Application Support/Jamf/tmp/` 위치를 모니터링하여 관리자가 실행하려는 **사용자 정의 스크립트**를 Jamf를 통해 실행하고 제거하는 것이 가능합니다. 이러한 스크립트에는 **자격 증명**이 포함될 수 있습니다.

그러나 **자격 증명**은 **매개 변수**로 이러한 스크립트를 통해 전달될 수 있으므로 `ps aux | grep -i jamf`를 모니터링해야 합니다(루트 권한이 필요하지 않음).

[**JamfExplorer.py** 스크립트](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py)는 새 파일이 추가되고 새 프로세스 인수를 수신할 수 있습니다.

### macOS 원격 액세스

또한 **MacOS**의 "특별한" **네트워크** **프로토콜**에 대해:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

일부 경우에는 **MacOS 컴퓨터가 AD에 연결**되어 있는 것을 발견할 수 있습니다. 이 시나리오에서는 일반적으로 사용하는 방식으로 **Active Directory를 열거**해야 합니다. 다음 페이지에서 도움을 얻을 수 있습니다:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

도움이 될 수 있는 **로컬 MacOS 도구** 중 하나는 `dscl`입니다:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
또한 MacOS용 도구들이 AD를 자동으로 열거하고 kerberos와 상호 작용할 수 있도록 준비되어 있습니다:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound는 Bloodhound 감사 도구의 확장으로, MacOS 호스트에서 Active Directory 관계를 수집하고 흡수할 수 있도록 합니다.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost는 macOS에서 Heimdal krb5 API와 상호 작용하도록 설계된 Objective-C 프로젝트입니다. 이 프로젝트의 목표는 대상 시스템에 다른 프레임워크나 패키지가 필요하지 않도록 네이티브 API를 사용하여 macOS 장치에서 Kerberos 주변의 보안 테스트를 가능하게 하는 것입니다.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory 열거를 수행하는 JavaScript for Automation (JXA) 도구입니다.

### 도메인 정보
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### 사용자

맥OS 사용자의 세 가지 유형은 다음과 같습니다:

- **로컬 사용자** — 로컬 OpenDirectory 서비스에서 관리되며 Active Directory와는 연결되어 있지 않습니다.
- **네트워크 사용자** — DC 서버에 연결하여 인증을 받아야 하는 휘발성 Active Directory 사용자입니다.
- **모바일 사용자** — 자격 증명 및 파일에 대한 로컬 백업이 있는 Active Directory 사용자입니다.

사용자 및 그룹에 대한 로컬 정보는 _/var/db/dslocal/nodes/Default_ 폴더에 저장됩니다.\
예를 들어, _mark_라는 사용자에 대한 정보는 _/var/db/dslocal/nodes/Default/users/mark.plist_에 저장되며, _admin_ 그룹에 대한 정보는 _/var/db/dslocal/nodes/Default/groups/admin.plist_에 저장됩니다.

HasSession 및 AdminTo 엣지를 사용하는 것 외에도, **MacHound는 Bloodhound 데이터베이스에 세 가지 새로운 엣지를 추가**합니다:

- **CanSSH** - 호스트로 SSH 연결을 허용하는 엔티티
- **CanVNC** - 호스트로 VNC 연결을 허용하는 엔티티
- **CanAE** - 호스트에서 AppleEvent 스크립트를 실행할 수 있는 엔티티
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
더 많은 정보: [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## 키체인 액세스

키체인에는 민감한 정보가 많이 포함되어 있으며, 프롬프트를 생성하지 않고 액세스하는 경우 레드팀 연습을 진행하는 데 도움이 될 수 있습니다:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## 외부 서비스

MacOS Red Teaming은 일반적인 Windows Red Teaming과 다르며, **일반적으로 MacOS는 여러 외부 플랫폼과 직접 통합**됩니다. MacOS의 일반적인 구성은 **OneLogin 동기화 자격 증명을 사용하여 컴퓨터에 액세스하고 OneLogin을 통해 여러 외부 서비스**(예: github, aws...)에 액세스하는 것입니다.

## 기타 레드팀 기술

### Safari

Safari에서 파일을 다운로드하면 "안전한" 파일인 경우 **자동으로 열립니다**. 예를 들어, **zip 파일을 다운로드**하면 자동으로 압축이 해제됩니다:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## 참고 자료

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
