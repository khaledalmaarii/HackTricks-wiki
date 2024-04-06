# Active Directory Methodology

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요. 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 기본 개요

**Active Directory**는 **네트워크 관리자**가 네트워크 내에서 **도메인**, **사용자**, **객체**를 효율적으로 생성하고 관리할 수 있도록 하는 기초 기술로 작동합니다. 이는 규모를 확장할 수 있도록 설계되어 다양한 수준에서 **그룹** 및 **하위 그룹**으로 사용자를 구성하고 **액세스 권한**을 제어합니다.

**Active Directory**의 구조는 세 가지 주요 레이어로 구성됩니다: **도메인**, **트리**, **포레스트**. **도메인**은 **사용자** 또는 **장치**와 같은 객체의 컬렉션을 포함하며 공통 데이터베이스를 공유합니다. **트리**는 이러한 도메인을 공유 구조로 연결한 그룹이며, **포레스트**는 상호 신뢰 관계를 통해 연결된 여러 트리의 컬렉션으로 조직 구조의 최상위 레이어를 형성합니다. 각 레벨에서 특정 **액세스** 및 **통신 권한**을 지정할 수 있습니다.

**Active Directory**의 주요 개념은 다음과 같습니다:

1. **디렉터리** - Active Directory 객체에 관련된 모든 정보를 보유합니다.
2. **객체** - **사용자**, **그룹**, **공유 폴더** 등 디렉터리 내의 개체를 나타냅니다.
3. **도메인** - 디렉터리 개체를 포함하는 컨테이너로, 각각 자체 개체 컬렉션을 유지하는 **포레스트** 내에서 여러 도메인이 공존할 수 있습니다.
4. **트리** - 공통 루트 도메인을 공유하는 도메인의 그룹입니다.
5. **포레스트** - Active Directory의 조직 구조의 정점으로, 상호 신뢰 관계를 통해 연결된 여러 트리로 구성됩니다.

\*\*Active Directory 도메인 서비스 (AD DS)\*\*는 네트워크 내에서 중앙 집중식 관리와 통신에 필수적인 다양한 서비스를 포함합니다. 이러한 서비스는 다음과 같습니다:

1. **도메인 서비스** - 데이터 저장을 중앙화하고 **사용자**와 **도메인** 간의 상호 작용을 관리합니다. 이는 **인증** 및 **검색** 기능을 포함합니다.
2. **인증서 서비스** - 안전한 **디지털 인증서**의 생성, 배포 및 관리를 감독합니다.
3. **경량 디렉터리 서비스** - **LDAP 프로토콜**을 통해 디렉터리 기능을 지원합니다.
4. **디렉터리 연합 서비스** - 단일 세션에서 여러 웹 애플리케이션에 대한 **단일 로그인** 기능을 제공합니다.
5. **권한 관리** - 무단 배포 및 사용을 규제하여 저작권 자료를 보호하는 데 도움을 줍니다.
6. **DNS 서비스** - **도메인 이름**의 해결에 중요합니다.

더 자세한 설명은 다음을 참조하세요: [**TechTerms - Active Directory 정의**](https://techterms.com/definition/active\_directory)

### **Kerberos 인증**

AD를 **공격하기 위해**는 **Kerberos 인증 프로세스**를 **정말 잘 이해**해야 합니다.\
[**작동 방식을 아직 모른다면 이 페이지를 읽으세요.**](kerberos-authentication.md)

## 치트 시트

[https://wadcoms.github.io/](https://wadcoms.github.io)에서 실행할 수 있는 명령어를 빠르게 확인하려면 이곳으로 이동하세요.

## Active Directory 탐색 (인증/세션 없음)

AD 환경에 액세스할 수는 있지만 자격 증명/세션이 없는 경우 다음을 수행할 수 있습니다:

* **네트워크 펜테스트:**
* 네트워크를 스캔하고 기기를 찾아 열린 포트에서 **취약점을 이용**하거나 **자격 증명을 추출**해 볼 수 있습니다 (예: [프린터는 매우 흥미로운 대상일 수 있습니다](ad-information-in-printers.md)).
* DNS 열거를 통해 도메인의 주요 서버에 대한 정보를 얻을 수 있습니다. 웹, 프린터, 공유, VPN, 미디어 등.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* 더 자세한 정보는 일반적인 [**펜테스트 방법론**](../../generic-methodologies-and-resources/pentesting-methodology.md)을 참조하세요.
* **SMB 서비스에서 null 및 Guest 액세스 확인** (최신 Windows 버전에서는 작동하지 않음):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* SMB 서버 열거에 대한 자세한 가이드는 다음에서 찾을 수 있습니다:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **LDAP 열거**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* LDAP 열거에 대한 자세한 가이드는 다음에서 찾을 수 있습니다 (특히 익명

### 사용자 열거

* **익명 SMB/LDAP 열거:** [**펜테스팅 SMB**](../../network-services-pentesting/pentesting-smb/) 및 [**펜테스팅 LDAP**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하세요.
* **Kerbrute 열거**: **유효하지 않은 사용자 이름이 요청**되면 서버는 **Kerberos 오류** 코드 \_KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN\_를 사용하여 사용자 이름이 잘못되었음을 확인할 수 있습니다. **유효한 사용자 이름**은 AS-REP 응답에서 **TGT**를 나타내거나 사용자가 사전 인증을 수행해야 함을 나타내는 _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_ 오류를 일으킬 것입니다.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```

* **OWA (Outlook Web Access) 서버**

네트워크에서 이러한 서버 중 하나를 찾았다면 **사용자 열거(user enumeration)를 수행**할 수도 있습니다. 예를 들어, [**MailSniper**](https://github.com/dafthack/MailSniper) 도구를 사용할 수 있습니다.

```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```

{% hint style="warning" %}
[**이 github 저장소**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)와 이것 ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))에서 사용자 이름 목록을 찾을 수 있습니다.

그러나, 이전에 수행한 탐색 단계에서 **회사에서 일하는 사람들의 이름**을 알아야 합니다. 이름과 성을 가지고 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 스크립트를 사용하여 유효한 사용자 이름을 생성할 수 있습니다.
{% endhint %}

### 하나 또는 여러 사용자 이름을 알고 있는 경우

좋아요, 이미 유효한 사용자 이름을 알고 있지만 암호는 모르는 경우... 다음을 시도해보세요:

* [**ASREPRoast**](asreproast.md): 사용자가 _DONT\_REQ\_PREAUTH_ 속성을 **가지고 있지 않은 경우**, 해당 사용자에 대해 **AS\_REP 메시지를 요청**할 수 있으며, 이 메시지에는 사용자의 암호의 파생으로 암호화된 일부 데이터가 포함됩니다.
* [**Password Spraying**](password-spraying.md): 발견된 각 사용자에 대해 가장 **일반적인 암호**를 시도해보세요. 어떤 사용자가 약한 암호를 사용하고 있는지 확인할 수 있습니다 (암호 정책을 염두에 두세요!).
* 또한 사용자의 메일 서버에 액세스하려고 **OWA 서버에 스프레이**를 시도하여 액세스 권한을 얻을 수도 있습니다.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS 독촉

네트워크의 일부 프로토콜을 **독촉**하여 일부 도전 **해시**를 얻을 수 있습니다:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML 릴레이

Active Directory를 열거했다면 **더 많은 이메일과 네트워크에 대한 이해**를 얻을 수 있습니다. AD 환경에 액세스하기 위해 NTML [**릴레이 공격**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)을 시도할 수 있습니다.

### NTLM 자격 증명 도용

**null 또는 guest 사용자**로 다른 PC 또는 공유에 액세스할 수 있다면, SCF 파일과 같은 **파일을 배치**하여 어떤식으로든 액세스되면 **자격 증명 도용을 유발**하여 NTLM 도전을 훔칠 수 있습니다:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## 자격 증명/세션을 사용하여 Active Directory 열거

이 단계에서는 **유효한 도메인 계정의 자격 증명 또는 세션을 침해**해야 합니다. 유효한 자격 증명이나 도메인 사용자로서의 셸을 가지고 있다면, **이전에 제시된 옵션은 여전히 다른 사용자를 침해하는 옵션**임을 기억해야 합니다.

인증된 열거를 시작하기 전에 **Kerberos 이중 호핑 문제**를 알아야 합니다.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### 열거

계정을 침해하는 것은 전체 도메인을 침해하기 위한 **큰 단계**입니다. 왜냐하면 **Active Directory 열거**를 시작할 수 있기 때문입니다:

[**ASREPRoast**](asreproast.md)에 관해서는 이제 모든 가능한 취약한 사용자를 찾을 수 있으며, [**Password Spraying**](password-spraying.md)에 관해서는 **모든 사용자 이름 목록**을 얻고 침해된 계정의 암호, 빈 암호 및 새로운 유망한 암호를 시도할 수 있습니다.

* [**CMD를 사용하여 기본 탐색 수행**](../basic-cmd-for-pentesters.md#domain-info)
* 더 은밀한 [**powershell을 사용하여 탐색**](../basic-powershell-for-pentesters/)
* 더 자세한 정보를 추출하기 위해 [**powerview를 사용**](../basic-powershell-for-pentesters/powerview.md)
* Active Directory에서 탐색을 위한 놀라운 도구인 [**BloodHound**](bloodhound.md). (사용하는 수집 방법에 따라) **매우 은밀하지 않을 수 있지만**, 이를 신경 쓰지 않는다면 꼭 시도해보세요. 사용자가 RDP를 할 수 있는 위치, 다른 그룹으로의 경로 등을 찾을 수 있습니다.
* **다른 자동화된 AD 열거 도구:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**AD의 DNS 레코드**](ad-dns-records.md)는 흥미로운 정보를 포함할 수 있습니다.
* **GUI 도구**인 **SysInternal Suite**의 **AdExplorer.exe**를 사용하여 디렉토리를 열거할 수 있습니다.
* _userPassword_ 및 _unixUserPassword_ 필드에서 자격 증명을 찾거나 \_Description\_을 위해 **LDAP 데이터베이스에서 ldapsearch**를 사용할 수도 있습니다. 다른 방법은 [PayloadsAllTheThings의 AD 사용자 코멘트에 있는 Password](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)를 참조하세요.
* **Linux**을 사용한다면 [**pywerview**](https://github.com/the-useless-one/pywerview)를 사용하여 도메인을 열거할 수도 있습니다.
* 다음과 같은 자동화된 도구를 시도해볼 수도 있습니다:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
* **모든 도메인 사용자 추출**

Windows에서 도메인 사용자 이름을 얻는 것은 매우 쉽습니다 (`net user /domain`, `Get-DomainUser` 또는 `wmic useraccount get name,sid`). Linux에서는 다음을 사용할 수 있습니다: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>`

> 이 열거 섹션은 작아 보일 수 있지만, 이것이 가장 중요한 부분입니다. 링크(특히 cmd, powershell, powerview 및 BloodHound)에 액세스하여 도메인을 열거하는 방법을 배우고 익숙해질 때까지 연습하세요. 평가 중에 이 부분은 DA로 가는 길을 찾거나 아무것도 할 수 없다고 결정하는 핵심적인 순간이 될 것입니다.

### Kerberoast

Kerberoasting은 사용자 계정에 연결된 서비스에서 사용되는 **TGS 티켓**을 얻고, 그들의 암호화를 **오프라인**으로 크래킹하는 것입니다. 이 암호화는 사용자 암호를 기반으로 합니다.

자세한 내

### 원격 연결 (RDP, SSH, FTP, Win-RM 등)

일부 자격 증명을 획득한 후에는 어떤 **기기에 접근할 수 있는지** 확인할 수 있습니다. 이를 위해 **CrackMapExec**을 사용하여 포트 스캔에 따라 다양한 프로토콜로 여러 서버에 연결을 시도할 수 있습니다.

### 로컬 권한 상승

만약 획득한 자격 증명이나 일반 도메인 사용자로서의 세션이 있고, **도메인 내의 어떤 기기에도 접근할 수 있는 경우**, 로컬 권한 상승 경로를 찾아 **자격 증명을 탈취**해야 합니다. 이는 로컬 관리자 권한만으로 메모리(LSASS)와 로컬(SAM)에서 다른 사용자의 해시를 덤프할 수 있기 때문입니다.

이 책에는 [**Windows에서의 로컬 권한 상승**](../windows-local-privilege-escalation/)에 대한 전체 페이지와 [**체크리스트**](../checklist-windows-privilege-escalation.md)가 있습니다. 또한 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)를 사용하는 것을 잊지 마세요.

### 현재 세션 티켓

현재 사용자의 **티켓**에서 예상치 못한 리소스에 **접근할 수 있는 권한**을 얻을 가능성은 매우 **낮습니다**. 그러나 다음을 확인할 수 있습니다:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTML Relay

만약 액티브 디렉토리를 열거할 수 있다면, **더 많은 이메일과 네트워크에 대한 더 나은 이해**를 얻을 수 있습니다. NTML [**릴레이 공격**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**을 강제로 실행할 수도 있습니다.**

### 컴퓨터 공유에서 자격 증명 찾기

기본 자격 증명을 얻었다면, AD 내에서 **공유되는 흥미로운 파일을 찾을 수 있는지 확인**해야 합니다. 이 작업을 수동으로 수행할 수도 있지만, 매우 지루하고 반복적인 작업입니다 (특히 체크해야 할 수백 개의 문서를 찾은 경우).

[**다음 링크를 따라가서 사용할 수 있는 도구에 대해 알아보세요.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### NTLM 자격 증명 도용

다른 PC나 공유에 **접근할 수 있다면** (예: SCF 파일과 같은) **파일을 배치**하여 어떤 방식으로든 **당신에 대한 NTML 인증을 유발**시킬 수 있습니다. 이렇게 하면 NTLM 도전을 **훔쳐내**서 크랙할 수 있습니다:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 취약점은 인증된 사용자가 도메인 컨트롤러를 **침해**할 수 있도록 했습니다.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## 특권 상승 (Privilege escalation) - 특권 있는 자격 증명/세션을 사용한 Active Directory

**다음 기술들은 일반 도메인 사용자만으로는 충분하지 않으며, 이러한 공격을 수행하기 위해 특별한 권한/자격 증명이 필요합니다.**

### 해시 추출

[AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 및 릴레이를 포함한 [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [로컬 특권 상승](../windows-local-privilege-escalation/)을 사용하여 일부 로컬 관리자 계정을 **침해**했다면, 이제 메모리와 로컬에 저장된 모든 해시를 덤프해야 합니다.\
[**다양한 방법으로 해시를 얻는 방법에 대해 이 페이지를 읽어보세요.**](https://github.com/carlospolop/hacktricks/blob/kr/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 해시 전달 (Pass the Hash)

사용자의 해시를 얻은 후, 해당 해시를 사용하여 사용자를 **가장**할 수 있습니다.\
해당 **해시를 사용하여 NTLM 인증을 수행하는 도구**를 사용해야 합니다. 또는 새로운 **세션로그온**을 생성하고 해당 **해시를 LSASS에 주입**하여 **NTLM 인증이 수행될 때 해당 해시가 사용**되도록 할 수도 있습니다. 마지막 옵션은 mimikatz가 수행하는 작업입니다.\
[**자세한 정보는 이 페이지를 읽어보세요.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

이 공격은 일반적인 Pass The Hash over NTLM 프로토콜 대신 사용자 NTLM 해시를 사용하여 Kerberos 티켓을 요청하는 것을 목표로 합니다. 따라서 NTLM 프로토콜이 비활성화되고 인증 프로토콜로 Kerberos만 허용되는 네트워크에서 특히 유용할 수 있습니다.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

**Pass The Ticket (PTT)** 공격 방법에서는 사용자의 암호나 해시 값 대신 인증 티켓을 **훔쳐**옵니다. 이 훔친 티켓은 사용자를 **가장**하여 네트워크 내의 리소스와 서비스에 무단으로 액세스할 수 있습니다.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### 자격 증명 재사용

로컬 관리자의 **해시**나 **비밀번호**를 가지고 있다면 해당 자격 증명으로 다른 **PC에 로컬로 로그인**해 보세요.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

{% hint style="warning" %}
이것은 상당히 **잡음이 많으며**, **LAPS**를 사용하면 이를 완화할 수 있습니다.
{% endhint %}

### MSSQL 남용 및 신뢰할 수 있는 링크

사용자가 **MSSQL 인스턴스에 액세스할 수 있는 권한**이 있다면, MSSQL 호스트에서 명령을 **실행**하거나 (SA로 실행 중인 경우) NetNTLM **해시를 탈취**하거나 심지어 **릴레이 공격**을 수행할 수 있습니다.\
또한, MSSQL 인스턴스가 다른 MSSQL 인스턴스에게 신뢰(데이터베이스 링크)를 받았다면, 사용자가 신뢰받은 데이터베이스에 대한 권한을 가지고 있다면 다른 인스턴스에서도 쿼리를 실행할 수 있습니다. 이러한 신뢰는 연쇄적으로 작동하며, 어느 시점에서는 사용자가 명령을 실행할 수 있는 잘못 구성된 데이터베이스를 찾을 수도 있습니다.\
**데이터베이스 간 링크는 포리스트 신뢰를 통해 작동합니다.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### 제한되지 않은 위임

[ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) 속성을 가진 컴퓨터 객체를 찾고 해당 컴퓨터에 도메인 권한이 있는 경우, 해당 컴퓨터에 로그인하는 모든 사용자의 TGT를 메모리에서 덤프 할 수 있습니다.\
따라서, **도메인 관리자가 해당 컴퓨터에 로그인**하면 그의 TGT를 덤프하고 [티켓 전달](pass-the-ticket.md)을 사용하여 그를 가장할 수 있습니다.\
제한된 위임을 통해 **프린트 서버를 자동으로 공격**할 수도 있습니다 (행운이 따르길 바랍니다).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### 제한된 위임

사용자 또는 컴퓨터가 "제한된 위임"에 허용되어 있다면, 해당 사용자/컴퓨터는 컴퓨터에서 일부 서비스에 액세스하기 위해 **임의의 사용자를 가장할 수 있습니다**.\
그런 다음, 이 사용자/컴퓨터의 해시를 **탈취**하면 (도메인 관리자 포함) 일부 서비스에 액세스하기 위해 **임의의 사용자**를 가장할 수 있습니다.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### 리소스 기반 제한된 위임

원격 컴퓨터의 Active Directory 개체에 대한 **쓰기** 권한을 가지면 **상승된 권한**으로 코드 실행이 가능합니다:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACL 남용

침해된 사용자는 일부 도메인 개체에 대한 **흥미로운 권한**을 가질 수 있으며, 이를 통해 측면 이동/권한 상승이 가능합니다.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### 프린터 스풀러 서비스 남용

도메인 내에서 **스풀 서비스가 수신 대기** 중인 것을 발견하면, 이를 **남용**하여 새로운 자격 증명을 획득하고 권한을 상승시킬 수 있습니다.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### 제3자 세션 남용

**다른 사용자**가 **침해된** 컴퓨터에 **접근**하는 경우, 메모리에서 자격 증명을 **수집**하고 그들의 프로세스에 **비콘을 삽입**하여 그들을 가장할 수 있습니다.\
일반적으로 사용자는 RDP를 통해 시스템에 접속하므로, 여기에서는 제3자 RDP 세션에 대한 몇 가지 공격을 수행하는 방법을 제공합니다:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS**는 도메인에 가입된 컴퓨터의 **로컬 관리자 암호**를 관리하기 위한 시스템을 제공하여, 암호가 **임의로 생성되고 고유하며 자주 변경**되도록 합니다. 이러한 암호는 Active Directory에 저장되며, 액세스는 권한이 있는 사용자에게만 허용됩니다. 이러한 암호에 대한 액세스 권한이 충분하면, 다른 컴퓨터로 피벗팅이 가능해집니다.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### 인증서 도난

침해된 컴퓨터에서 **인증서를 수집**하는 것은 환경 내에서 권한 상승하는 방법일 수 있습니다:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### 인증서 템플릿 남용

**취약한 템플릿**이 구성되어 있다면, 권한 상승을 위해 이를 남용할 수 있습니다:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## 고권한 계정으로 후처리

### 도메인 자격 증명 덤프

**도메인 관리자** 또는 더 나은 **엔터프라이즈 관리자** 권한을 획득하면, 도메인 데이터베이스인 \_ntds.dit\_를 **덤프**할 수 있습니다.

[**DCSync 공격에 대한 자세한 정보는 여기에서 찾을 수 있습니다**](dcsync.md).

[**NTDS.dit를 탈취하는 방법에 대한 자세한 정보는 여기에서 찾을 수 있습니다**](https://github.com/carlospolop/hacktricks/blob/kr/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 권한 상승으로서의 영속성

이전에 논의된 일부 기술은 영속성을 위해 사용될 수 있습니다.\
예를 들어 다음과 같은 작업을 수행할 수 있습니다:

* 사용자를 [**Kerberoast**](kerberoast.md)에 취약하게 만들기

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

* 사용자를 [**ASREPRoast**](asreproast.md)에 취약하게 만들기

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

* 사용자에게 [**DCSync**](./#dcsync) 권한 부여

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### 실버 티켓

**실버 티켓 공격**은 특정 서비스를 위해 **합법적인 티켓 발급 서비스 (TGS) 티켓**을 생성하는 것입니다. 이를 위해 NTLM 해시 (예: PC 계정의 해시)를 사용합니다. 이 방법은 서비스 권한에 액세스하기 위해 사용

### **인증서 도메인 지속성**

**인증서를 사용하여 도메인 내에서 높은 권한으로 지속성을 유지할 수도 있습니다:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder 그룹

Active Directory의 **AdminSDHolder** 개체는 **Domain Admins** 및 **Enterprise Admins**와 같은 **특권 그룹**의 보안을 보장하기 위해 이러한 그룹에 대해 표준 \*\*액세스 제어 목록 (ACL)\*\*을 적용하여 무단 변경을 방지합니다. 그러나 이 기능은 악용될 수 있습니다. 공격자가 AdminSDHolder의 ACL을 수정하여 일반 사용자에게 완전한 액세스 권한을 부여하면 해당 사용자는 모든 특권 그룹에 대해 광범위한 제어권을 획득합니다. 이 보안 조치는 보호를 위해 만들어진 것이지만, 감시가 철저하지 않으면 무단 액세스가 허용될 수 있습니다.

[**AdminDSHolder 그룹에 대한 자세한 정보는 여기에서 확인하세요.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM 자격 증명

모든 **도메인 컨트롤러 (DC)** 내에는 **로컬 관리자** 계정이 존재합니다. 이러한 컴퓨터에서 관리자 권한을 얻으면 **mimikatz**를 사용하여 로컬 관리자 해시를 추출할 수 있습니다. 이후 레지스트리 수정이 필요하며, 이를 통해 이 패스워드를 사용할 수 있도록 설정하여 로컬 관리자 계정에 원격 액세스를 허용할 수 있습니다.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL 지속성

특정 도메인 개체에 대해 **사용자**에게 **특별한 권한**을 부여하여 사용자가 **나중에 권한을 상승**시킬 수 있습니다.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### 보안 기술자

**보안 기술자**는 **객체**가 **객체**에 대해 **가지는 권한**을 **저장**하는 데 사용됩니다. 객체의 보안 기술자에 **작은 변경**만 가해도 특권 그룹의 구성원이 아니어도 해당 객체에 대해 매우 흥미로운 권한을 얻을 수 있습니다.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

메모리에서 **LSASS**를 변경하여 모든 도메인 계정에 대한 액세스 권한을 부여하는 **일반적인 패스워드**를 설정합니다.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### 사용자 정의 SSP

[여기에서 SSP (보안 지원 공급자)가 무엇인지 알아보세요.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
**자체 SSP**를 생성하여 기계에 액세스하는 데 사용되는 **자격 증명**을 **평문으로 캡처**할 수 있습니다.

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

AD에 **새로운 도메인 컨트롤러**를 등록하고 지정된 개체에 대해 **로그를 남기지 않고** 속성 (SIDHistory, SPN 등)을 **전송**합니다. **DA** 권한이 필요하며 **루트 도메인** 내에 있어야 합니다.\
잘못된 데이터를 사용하면 상당히 나쁜 로그가 표시됩니다.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS 지속성

이전에는 **LAPS 패스워드를 읽을 수 있는 충분한 권한**이 있다면 권한 상승하는 방법에 대해 논의했습니다. 그러나 이러한 패스워드는 **지속성을 유지하는 데도 사용**될 수 있습니다.\
확인:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## 포레스트 권한 상승 - 도메인 신뢰

Microsoft는 **포레스트**를 보안 경계로 간주합니다. 이는 **단일 도메인을 침해하는 것이 전체 포레스트를 침해하는 것으로 이어질 수 있다는 것을 의미**합니다.

### 기본 정보

[**도메인 신뢰**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx)는 한 **도메인**의 사용자가 다른 **도메인**의 리소스에 액세스할 수 있도록 하는 보안 메커니즘입니다. 이는 두 도메인의 인증 시스템을 연결하여 인증 확인을 원활하게 수행할 수 있도록 연결을 생성합니다. 도메인이 신뢰를 설정하면, 도메인 컨트롤러(DC) 간에 교환 및 특정 **키**를 유지합니다. 이 키는 신뢰의 무결성에 중요한 역할을 합니다.

일반적인 시나리오에서, 사용자가 **신뢰된 도메인**의 서비스에 액세스하려면, 먼저 자신의 도메인의 DC에서 **inter-realm TGT**라고 하는 특수한 티켓을 요청해야 합니다. 이 TGT는 두 도메인이 합의한 공유 **키**로 암호화됩니다. 그런 다음 사용자는 이 TGT를 **신뢰된 도메인의 DC**에 제출하여 서비스 티켓(**TGS**)을 받습니다. 신뢰된 도메인의 DC가 inter-realm TGT를 성공적으로 확인하면, 사용자에게 서비스에 대한 액세스 권한을 부여하는 TGS를 발급합니다.

**단계**:

1. **Domain 1**의 **클라이언트 컴퓨터**가 **NTLM 해시**를 사용하여 \*\*Domain Controller (DC1)\*\*에서 \*\*Ticket Granting Ticket (TGT)\*\*를 요청합니다.
2. 클라이언트가 성공적으로 인증되면 DC1은 새로운 TGT를 발급합니다.
3. 클라이언트는 **Domain 2**의 리소스에 액세스하기 위해 DC1에서 **inter-realm TGT**를 요청합니다.
4. inter-realm TGT는 DC1과 DC2 사이에서 공유되는 **신뢰 키**로 암호화됩니다.
5. 클라이언트는 inter-realm TGT를 \*\*Domain 2의 도메인 컨트롤러 (DC2)\*\*로 가져갑니다.
6. DC2는 공유 신뢰 키를 사용하여 inter-realm TGT를 확인하고 유효한 경우, 클라이언트가 액세스하려는 Domain 2의 서버에 대한 \*\*Ticket Granting Service (TGS)\*\*를 발급합니다.
7. 마지막으로, 클

#### **신뢰 관계**의 다른 차이점

* 신뢰 관계는 **추이적**일 수도 있습니다 (A가 B를 신뢰하고, B가 C를 신뢰하면 A는 C를 신뢰합니다) 또는 **비추이적**일 수도 있습니다.
* 신뢰 관계는 **양방향 신뢰** (둘 다 서로를 신뢰) 또는 **일방적 신뢰** (한 쪽만 다른 쪽을 신뢰)로 설정할 수 있습니다.

### 공격 경로

1. 신뢰 관계를 **열거**합니다.
2. **보안 주체** (사용자/그룹/컴퓨터) 중 어떤 것이 **다른 도메인**의 리소스에 **액세스**할 수 있는지 확인합니다. 아마도 ACE 항목이나 다른 도메인의 그룹에 속해 있는지 확인합니다. **도메인 간의 관계**를 찾습니다 (아마도 신뢰가 이를 위해 생성되었을 것입니다).
3. 이 경우 kerberoast도 다른 옵션일 수 있습니다.
4. 도메인을 통해 **피벗**할 수 있는 **계정**을 **침해**합니다.

공격자는 다른 도메인의 리소스에 접근할 수 있는 세 가지 주요 메커니즘을 사용할 수 있습니다:

* **로컬 그룹 멤버십**: 주체는 서버의 "Administrators" 그룹과 같은 기계의 로컬 그룹에 추가될 수 있으며, 이를 통해 해당 기계를 통제할 수 있습니다.
* **외부 도메인 그룹 멤버십**: 주체는 외부 도메인 내의 그룹의 구성원이 될 수도 있습니다. 그러나 이 방법의 효과는 신뢰의 성격과 그룹의 범위에 따라 다릅니다.
* **액세스 제어 목록 (ACL)**: 주체는 특정 리소스에 액세스할 수 있도록 **ACL**에 지정될 수 있습니다. 특히 **DACL** 내의 **ACE**로서 지정될 수 있습니다. ACL, DACL 및 ACE의 작동 원리에 대해 자세히 알아보려면 "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)"라는 백서를 참조하면 됩니다.

### 자식 도메인에서 부모 도메인으로의 권한 상승

```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```

{% hint style="warning" %}
**2개의 신뢰할 수 있는 키**가 있습니다. 하나는 \_자식 --> 부모\_를 위한 것이고, 다른 하나는 _부모_ --> \_자식\_을 위한 것입니다.\
현재 도메인에서 사용되는 키를 확인하려면 다음을 사용할 수 있습니다:

```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

SID-History Injection을 이용하여 자식/부모 도메인으로 엔터프라이즈 관리자 권한 상승:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### 쓰기 가능한 Configuration NC 악용

Configuration Naming Context (NC)가 어떻게 악용될 수 있는지 이해하는 것이 중요합니다. Configuration NC는 Active Directory (AD) 환경에서 포레스트 전체의 구성 데이터를 중앙 저장소로 제공합니다. 이 데이터는 포레스트 내의 모든 도메인 컨트롤러 (DC)에 복제되며, 쓰기 가능한 DC는 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 악용하기 위해서는 **DC에서 SYSTEM 권한**을 가져야 합니다. 가능하면 자식 DC에서 이 작업을 수행해야 합니다.

**루트 DC 사이트에 GPO 연결**

Configuration NC의 Sites 컨테이너에는 AD 포레스트 내의 모든 도메인에 가입한 컴퓨터의 사이트에 대한 정보가 포함되어 있습니다. 공격자는 DC에서 SYSTEM 권한으로 작업함으로써 GPO를 루트 DC 사이트에 연결할 수 있습니다. 이 작업은 이러한 사이트에 적용된 정책을 조작하여 루트 도메인을 잠재적으로 침해할 수 있습니다.

자세한 정보는 [SID 필터링 우회](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)에 대한 연구를 참고할 수 있습니다.

**포레스트 내의 임의의 gMSA 침해**

이 공격 벡터는 도메인 내의 특권 gMSA를 대상으로 합니다. gMSA의 암호를 계산하는 데 필요한 KDS Root 키는 Configuration NC에 저장됩니다. DC에서 SYSTEM 권한을 가지고 있다면 KDS Root 키에 액세스하여 포레스트 전체의 모든 gMSA의 암호를 계산할 수 있습니다.

자세한 분석은 [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)의 토론에서 찾을 수 있습니다.

**스키마 변경 공격**

이 방법은 새로운 특권 AD 객체의 생성을 기다리는 인내심을 필요로 합니다. SYSTEM 권한을 가진 공격자는 AD 스키마를 수정하여 모든 클래스에 대한 완전한 제어 권한을 부여할 수 있습니다. 이로 인해 무단 접근 및 새로 생성된 AD 객체에 대한 제어가 가능해질 수 있습니다.

자세한 내용은 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)에서 확인할 수 있습니다.

**ADCS ESC5를 통한 DA에서 EA로 상승**

ADCS ESC5 취약점은 공개 키 인프라 (PKI) 객체의 제어를 목표로 하여 포레스트 내의 모든 사용자로 인증할 수 있는 인증서 템플릿을 생성합니다. PKI 객체는 Configuration NC에 저장되므로 쓰기 가능한 자식 DC를 침해하여 ESC5 공격을 실행할 수 있습니다.

자세한 내용은 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)에서 확인할 수 있습니다. ADCS가 없는 시나리오에서는 공격자가 필요한 구성 요소를 설정할 수 있는 능력이 있습니다. 이에 대한 자세한 내용은 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)에서 논의되었습니다.

### 외부 포레스트 도메인 - 일방향 (수신) 또는 양방향

```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```

이 시나리오에서는 **외부 도메인이 신뢰**하는 도메인으로, **미확인된 권한**을 부여받습니다. **내 도메인의 주체가 외부 도메인에 어떤 액세스 권한을 가지고 있는지 찾은 다음 이를 악용**해야 합니다:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### 외부 포레스트 도메인 - 일방향 (외부로)

```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```

이 시나리오에서는 **도메인**이 **다른 도메인**의 주체에게 일부 **권한을 위임**하고 있습니다.

그러나 신뢰하는 도메인에 의해 신뢰되는 도메인이 신뢰하는 도메인에 의해 **예측 가능한 이름**을 가진 사용자를 **생성**하고 신뢰하는 암호로 사용한다는 것을 의미합니다. 이는 신뢰하는 도메인 내에서 사용자에게 접근하여 신뢰하는 도메인 내에서 열거하고 더 높은 권한을 승격시킬 수 있다는 것을 의미합니다:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

신뢰하는 도메인을 침해하는 또 다른 방법은 도메인 신뢰의 **반대 방향**에 생성된 [**SQL 신뢰 링크**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다 (이는 매우 흔하지 않습니다).

신뢰하는 도메인을 침해하는 또 다른 방법은 신뢰하는 도메인의 **사용자가 액세스할 수 있는** 기계에서 대기하는 것입니다. 그런 다음 공격자는 RDP 세션 프로세스에 코드를 삽입하고 거기에서 피해자의 원본 도메인에 **액세스**할 수 있습니다.\
또한, 피해자가 **하드 드라이브를 마운트**한 경우, 공격자는 RDP 세션 프로세스에서 **하드 드라이브의 시작 프로그램 폴더에 백도어**를 저장할 수 있습니다. 이 기술은 **RDPInception**이라고 합니다.

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### 도메인 신뢰 남용 완화

### **SID 필터링:**

* 포리스트 신뢰에서 SID 히스토리 속성을 활용한 공격 위험은 SID 필터링에 의해 완화됩니다. 이는 모든 포리스트 간 신뢰에 대해 기본적으로 활성화되어 있습니다. 이는 Microsoft의 입장에 따라 도메인이 아닌 포리스트를 보안 경계로 간주하기 때문에 포리스트 내 신뢰는 안전하다는 가정에 기반합니다.
* 그러나 주의해야 할 점이 있습니다. SID 필터링은 때때로 응용 프로그램 및 사용자 액세스에 문제가 발생할 수 있어 비활성화될 수 있습니다.

### **선택적 인증:**

* 포리스트 간 신뢰의 경우, 선택적 인증을 사용하여 두 포리스트의 사용자가 자동으로 인증되지 않도록 합니다. 대신, 신뢰하는 도메인이나 포리스트 내의 도메인 및 서버에 액세스하기 위해서는 명시적인 권한이 필요합니다.
* 이러한 조치는 쓰기 가능한 구성 네이밍 컨텍스트 (NC)의 악용이나 신뢰 계정에 대한 공격을 방지하지 않습니다.

[**ired.team에서 도메인 신뢰에 대한 자세한 정보**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## 일반적인 방어책

[**자격 증명 보호에 대한 자세한 내용은 여기에서 알아보세요.**](../stealing-credentials/credentials-protections.md)\\

### **자격 증명 보호를 위한 방어 조치**

* **도메인 관리자 제한**: 도메인 관리자는 도메인 컨트롤러에만 로그인할 수 있도록 하고 다른 호스트에서의 사용을 피하는 것이 좋습니다.
* **서비스 계정 권한**: 서비스는 도메인 관리자 (DA) 권한으로 실행되지 않도록하여 보안을 유지해야 합니다.
* **일시적인 권한 제한**: DA 권한이 필요한 작업의 경우, 그 지속 시간을 제한해야 합니다. 다음과 같이 수행할 수 있습니다: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **기만 기술 구현**

* 기만을 구현하기 위해서는 속일 수 있는 사용자나 컴퓨터와 같은 함정을 설정해야 합니다. 이를 위해 만료되지 않거나 신뢰할 수 있는 것으로 표시된 암호와 같은 기능을 갖춘 가짜 사용자나 컴퓨터를 생성하는 것이 포함됩니다.
* 구체적인 접근 방식에는 특정 권한을 갖는 사용자를 생성하거나 그들을 고권한 그룹에 추가하는 것이 포함됩니다.
* 실제 예제로는 다음과 같은 도구를 사용할 수 있습니다: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* 기만 기술을 배포하는 데 대한 자세한 내용은 [GitHub의 Deploy-Deception](https://github.com/samratashok/Deploy-Deception)에서 찾을 수 있습니다.

### **기만 식별**

* **사용자 개체의 경우**: 비정상적인 ObjectSID, 드물게 로그온하는 것, 생성 날짜 및 낮은 잘못된 암호 횟수 등이 의심스러운 지표입니다.
* **일반적인 지표**: 잠재적인 기만 개체의 속성을 실제 개체와 비교하여 일관성이 없는 부분을 발견할 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)와 같은 도구를 사용하여 이러한 기만을 식별하는 데 도움을 받을 수 있습니다.

### **탐지 시스템 우회**

* **Microsoft ATA 탐지 우회**:
* **사용자 열거**: ATA 탐지를 피하기 위해 도메인 컨트롤러에서 세션 열거를 피합니다.
* **티켓 위장**: 티켓 생성을 위해 **aes** 키를 사용하여 NTLM으로 다운그레이드하지 않아 탐지를 회피합니다.
* **DCSync 공격**: ATA 탐지를 피하기 위해 도메인 컨트롤러에서 직접 실행하는 대신 도메인 컨트롤러가 아닌 곳에서 실행하는 것이 좋습니다.

## 참고 자료

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드하려면 [**구독 플랜**](https://github.com/sponsors/carlospolop)을 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 확인하세요. 독점적

</details>
