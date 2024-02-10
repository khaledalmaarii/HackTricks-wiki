# Kerberos 이중 호핑 문제

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하세요.

</details>

## 소개

Kerberos "이중 호핑" 문제는 공격자가 **Kerberos 인증을 두 개의 호핑을 통해 사용**하려고 할 때 발생합니다. 예를 들어 **PowerShell**/**WinRM**을 사용하는 경우입니다.

**Kerberos**를 통해 **인증**이 발생할 때 **자격 증명**은 **메모리에 캐시되지 않습니다**. 따라서, 만약 mimikatz를 실행한다면, 사용자의 자격 증명을 머신에서 찾을 수 없습니다.

이는 Kerberos로 연결할 때 다음과 같은 단계를 거치기 때문입니다:

1. User1이 자격 증명을 제공하고 **도메인 컨트롤러**가 User1에게 Kerberos **TGT**를 반환합니다.
2. User1은 **TGT**를 사용하여 Server1에 **연결**하기 위해 **서비스 티켓**을 요청합니다.
3. User1은 **Server1**에 **연결**하고 **서비스 티켓**을 제공합니다.
4. **Server1**에는 User1의 자격 증명 또는 User1의 **TGT**가 **캐시되어 있지 않습니다**. 따라서, Server1에서 User1이 두 번째 서버에 로그인을 시도하면 **인증할 수 없습니다**.

### 제한되지 않은 위임

PC에서 **제한되지 않은 위임**이 활성화되어 있다면, **서버**는 액세스하는 각 사용자의 **TGT**를 **받게 됩니다**. 또한, 제한되지 않은 위임을 사용하면 해당 서버에서 **도메인 컨트롤러를 손상시킬 수 있습니다**.\
[**제한되지 않은 위임 페이지에서 자세한 정보**](unconstrained-delegation.md)를 확인하세요.

### CredSSP

이 문제를 피하는 또 다른 방법은 [**안전하지 않은**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) **Credential Security Support Provider**입니다. Microsoft에 따르면:

> CredSSP 인증은 사용자 자격 증명을 로컬 컴퓨터에서 원격 컴퓨터로 위임합니다. 이는 원격 작업의 보안 위험을 증가시킵니다. 원격 컴퓨터가 침해당하는 경우, 자격 증명이 전달되면 네트워크 세션을 제어하는 데 사용될 수 있습니다.

보안 문제로 인해 **CredSSP**는 프로덕션 시스템, 중요한 네트워크 및 유사한 환경에서 비활성화하는 것이 매우 권장됩니다. **CredSSP**가 활성화되어 있는지 확인하려면 `Get-WSManCredSSP` 명령을 실행할 수 있습니다. 이 명령은 **CredSSP 상태를 확인**할 수 있으며, **WinRM**이 활성화되어 있다면 원격으로 실행할 수도 있습니다.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## 해결 방법

### Invoke Command

더블 호핑 문제를 해결하기 위해 중첩된 `Invoke-Command`를 사용하는 방법이 제시됩니다. 이 방법은 문제를 직접 해결하지는 않지만 특별한 구성 없이 해결책을 제공합니다. 이 접근 방식은 초기 공격 머신에서 실행되는 PowerShell 명령 또는 이전에 설정된 첫 번째 서버와의 PS-세션을 통해 보조 서버에서 명령(`hostname`)을 실행할 수 있도록 합니다. 다음은 이 방법의 실행 방법입니다:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
또 다른 방법으로는 첫 번째 서버와 PS-세션을 설정하고 `$cred`를 사용하여 `Invoke-Command`을 실행하는 것이 작업을 중앙 집중화하는 데 도움이 됩니다.

### PSSession 구성 등록

더블 호핑 문제를 우회하기 위한 해결책으로 `Register-PSSessionConfiguration`을 `Enter-PSSession`과 함께 사용하는 방법이 있습니다. 이 방법은 `evil-winrm`과는 다른 접근 방식을 요구하며, 더블 호핑 제한이 없는 세션을 가능하게 합니다.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### 포트 포워딩

중간 대상에 대한 로컬 관리자의 경우, 포트 포워딩을 통해 요청을 최종 서버로 보낼 수 있습니다. `netsh`를 사용하여 포트 포워딩을 위한 규칙을 추가할 수 있으며, 포워딩된 포트를 허용하기 위해 Windows 방화벽 규칙도 추가할 수 있습니다.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe`는 WinRM 요청을 전달하는 데 사용될 수 있으며, PowerShell 모니터링이 우려되는 경우 감지가 어려울 수 있는 대안입니다. 아래 명령은 `winrs.exe`의 사용 예시를 보여줍니다:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

첫 번째 서버에 OpenSSH를 설치하면 더블 홉 문제에 대한 해결책을 제공하며, 특히 점프 박스 시나리오에 유용합니다. 이 방법은 CLI를 사용하여 Windows용 OpenSSH를 설치하고 설정하는 것을 요구합니다. 암호 인증을 구성하면 중개 서버가 사용자를 대신하여 TGT를 얻을 수 있습니다.

#### OpenSSH 설치 단계

1. 최신 OpenSSH 릴리스 zip 파일을 다운로드하고 대상 서버로 이동합니다.
2. 압축을 해제하고 `Install-sshd.ps1` 스크립트를 실행합니다.
3. 방화벽 규칙을 추가하여 포트 22를 열고 SSH 서비스가 실행 중인지 확인합니다.

`Connection reset` 오류를 해결하기 위해 OpenSSH 디렉토리에 대한 모든 사용자의 읽기 및 실행 권한을 허용하도록 권한을 업데이트해야 할 수도 있습니다.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## 참고 자료

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 기교를 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하세요.

</details>
