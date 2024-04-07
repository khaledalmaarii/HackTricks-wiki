# Kerberos Double Hop Problem

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)</strong>에서 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하고 싶으신가요? 혹은 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요, 저희의 독점적인 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* [**💬**](https://emojipedia.org/speech-balloon/) **Discord 그룹**에 **가입**하거나 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우**하세요.
* **해킹 요령을 공유하고 싶으시다면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **로 PR을 제출**해주세요.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## 소개

Kerberos "Double Hop" 문제는 **Kerberos 인증을 통해 두 개의** **호핑**을 시도할 때 발생합니다. 예를 들어 **PowerShell**/**WinRM**을 사용하는 경우입니다.

**Kerberos**를 통해 **인증**이 발생할 때 **자격 증명**이 **메모리에 캐시되지 않습니다.** 따라서 mimikatz를 실행해도 사용자의 자격 증명을 찾을 수 없습니다.

이는 Kerberos로 연결할 때 다음 단계를 거치기 때문입니다:

1. User1이 자격 증명을 제공하고 **도메인 컨트롤러**가 User1에게 Kerberos **TGT**를 반환합니다.
2. User1이 **TGT**를 사용하여 **Server1에 연결**할 **서비스 티켓**을 요청합니다.
3. User1이 **Server1에 연결**하고 **서비스 티켓**을 제공합니다.
4. **Server1**에는 User1의 자격 증명이 캐시되어 있지 않거나 User1의 **TGT**가 없습니다. 따라서 Server1에서 두 번째 서버에 로그인하려고 할 때 **인증할 수 없습니다.**

### Unconstrained Delegation

**비제약 위임**이 PC에서 활성화되어 있는 경우, **서버**는 액세스하는 각 사용자의 **TGT**를 **받게** 됩니다. 또한, 비제약 위임이 사용된 경우 아마도 **도메인 컨트롤러를** **손상시킬 수 있습니다.**\
[**비제약 위임 페이지에서 자세한 정보 확인**](unconstrained-delegation.md).

### CredSSP

이 문제를 피하는 또 다른 방법은 [**안전하지 않은**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) **Credential Security Support Provider**입니다. Microsoft에 따르면:

> CredSSP 인증은 로컬 컴퓨터의 사용자 자격 증명을 원격 컴퓨터로 위임합니다. 이 관행은 원격 작업의 보안 위험을 증가시킵니다. 원격 컴퓨터가 침해당한 경우 자격 증명이 전달되면 네트워크 세션을 제어하는 데 사용될 수 있습니다.

**CredSSP**를 프로덕션 시스템, 민감한 네트워크 및 유사한 환경에서 **비활성화**하는 것이 매우 권장됩니다. **CredSSP**가 활성화되어 있는지 확인하려면 `Get-WSManCredSSP` 명령을 실행할 수 있습니다. 이 명령을 사용하면 **CredSSP 상태를 확인**할 수 있으며, **WinRM**이 활성화되어 있다면 원격으로 실행할 수도 있습니다.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## 해결책

### Invoke Command

더블 호핑 문제를 해결하기 위해 중첩된 `Invoke-Command`를 활용하는 방법이 제시됩니다. 이 방법은 문제를 직접 해결하는 것은 아니지만 특별한 구성 없이 해결책을 제공합니다. 이 접근 방식을 사용하면 초기 공격 머신에서 실행되는 PowerShell 명령 또는 처음 서버와 이전에 설정된 PS-Session을 통해 초기 서버에서 두 번째 서버에서 명령(`hostname`)을 실행할 수 있습니다. 다음은 그 방법입니다:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
### PSSession 구성 등록

더블 홉 문제를 우회하는 해결책으로 `Register-PSSessionConfiguration`을 `Enter-PSSession`과 함께 사용하는 것이 제안됩니다. 이 방법은 `evil-winrm`과는 다른 접근 방식을 요구하며 더블 홉 제한을 겪지 않는 세션을 허용합니다.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### 포트포워딩

중간 대상의 로컬 관리자는 `netsh`를 사용하여 포트포워딩을 허용하는 규칙을 추가할 수 있습니다. 이를 통해 최종 서버로 요청을 보낼 수 있습니다. Windows 방화벽 규칙도 포워딩된 포트를 허용하도록 설정됩니다.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe`는 WinRM 요청을 전달하는 데 사용할 수 있으며 PowerShell 모니터링이 우려되는 경우 덜 감지되는 옵션으로 사용할 수 있습니다. 아래 명령은 그 사용법을 보여줍니다:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

첫 번째 서버에 OpenSSH를 설치하면 더블 홉 문제에 대한 해결책이 제공되며, 특히 점프 박스 시나리오에 유용합니다. 이 방법은 Windows용 OpenSSH의 CLI 설치와 설정을 필요로 합니다. 암호 인증으로 구성된 경우 중간 서버가 사용자를 대신하여 TGT를 획득할 수 있습니다.

#### OpenSSH 설치 단계

1. 최신 OpenSSH 릴리스 zip 파일을 다운로드하고 대상 서버로 이동합니다.
2. 압축 해제하고 `Install-sshd.ps1` 스크립트를 실행합니다.
3. 포트 22를 열기 위한 방화벽 규칙을 추가하고 SSH 서비스가 실행 중인지 확인합니다.

`Connection reset` 오류를 해결하려면, 권한을 업데이트하여 OpenSSH 디렉토리에서 모든 사용자가 읽기 및 실행 액세스를 허용해야 할 수 있습니다.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## 참고 자료

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>와 함께 **제로**에서 **히어로**로 **AWS 해킹 배우기**</summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에서 귀사 광고**를 보고 싶으신가요? 아니면 **PEASS의 최신 버전에 액세스**하거나 **PDF로 HackTricks를 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 받으세요
* [**💬**](https://emojipedia.org/speech-balloon/) **Discord 그룹** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**을 팔로우**하세요.
* **해킹 트릭을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 PR을 제출**하세요.

</details>
