# 스켈레톤 키

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

## 스켈레톤 키 공격

**스켈레톤 키 공격**은 공격자가 도메인 컨트롤러에 **마스터 비밀번호를 삽입**하여 **Active Directory 인증을 우회**할 수 있는 정교한 기술입니다. 이를 통해 공격자는 사용자의 비밀번호 없이 **모든 사용자로 인증**받아 도메인에 **무제한 액세스 권한**을 부여받을 수 있습니다.

[Mimikatz](https://github.com/gentilkiwi/mimikatz)를 사용하여 이 공격을 수행할 수 있습니다. 이 공격을 수행하기 위해서는 **도메인 관리자 권한이 필요**하며, 공격자는 포괄적인 침투를 위해 각 도메인 컨트롤러를 대상으로 설정해야 합니다. 그러나 이 공격의 효과는 일시적이며, 도메인 컨트롤러를 다시 시작하면 악성 코드가 제거되므로 지속적인 액세스를 위해 재구현해야 합니다.

**공격 실행**에는 `misc::skeleton`이라는 단일 명령이 필요합니다.

## 완화 방법

이러한 공격에 대한 완화 전략은 서비스 설치 또는 민감한 권한 사용을 나타내는 특정 이벤트 ID를 모니터링하는 것을 포함합니다. 특히, 시스템 이벤트 ID 7045 또는 보안 이벤트 ID 4673을 찾으면 수상한 활동을 확인할 수 있습니다. 또한, `lsass.exe`를 보호된 프로세스로 실행하는 것은 공격자의 노력을 크게 방해할 수 있으며, 이를 위해 커널 모드 드라이버를 사용해야 하므로 공격의 복잡성이 증가합니다.

보안 조치를 강화하기 위한 PowerShell 명령어는 다음과 같습니다:

- 수상한 서비스 설치를 감지하려면 다음을 사용하세요: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- 특히, Mimikatz의 드라이버를 감지하려면 다음 명령어를 사용할 수 있습니다: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- `lsass.exe`를 강화하기 위해 보호된 프로세스로 설정하는 것이 좋습니다: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

보호 조치가 성공적으로 적용되었는지 확인하기 위해 시스템 재부팅 후 검증이 필요합니다. 다음을 통해 이를 확인할 수 있습니다: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"`

## 참고 자료
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
