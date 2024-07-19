# 스켈레톤 키

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}

## 스켈레톤 키 공격

**스켈레톤 키 공격**은 공격자가 **마스터 비밀번호를 주입하여 Active Directory 인증을 우회**할 수 있게 해주는 정교한 기술입니다. 이를 통해 공격자는 **비밀번호 없이도 모든 사용자로 인증할 수 있으며**, 사실상 **도메인에 대한 무제한 접근 권한을 부여받습니다.**

이 공격은 [Mimikatz](https://github.com/gentilkiwi/mimikatz)를 사용하여 수행할 수 있습니다. 이 공격을 수행하기 위해서는 **도메인 관리자 권한이 필요하며**, 공격자는 포괄적인 침해를 보장하기 위해 각 도메인 컨트롤러를 목표로 해야 합니다. 그러나 공격의 효과는 일시적이며, **도메인 컨트롤러를 재시작하면 악성 코드가 제거되므로 지속적인 접근을 위해서는 재구현이 필요합니다.**

**공격을 실행하는 데 필요한 명령어**는 다음과 같습니다: `misc::skeleton`.

## 완화 조치

이러한 공격에 대한 완화 전략에는 서비스 설치 또는 민감한 권한 사용을 나타내는 특정 이벤트 ID를 모니터링하는 것이 포함됩니다. 특히, 시스템 이벤트 ID 7045 또는 보안 이벤트 ID 4673을 찾으면 의심스러운 활동을 드러낼 수 있습니다. 또한, `lsass.exe`를 보호된 프로세스로 실행하면 공격자의 노력을 상당히 저해할 수 있으며, 이는 커널 모드 드라이버를 사용해야 하므로 공격의 복잡성이 증가합니다.

보안 조치를 강화하기 위한 PowerShell 명령어는 다음과 같습니다:

- 의심스러운 서비스 설치를 감지하려면 다음을 사용하세요: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- 특히 Mimikatz의 드라이버를 감지하기 위해 다음 명령어를 사용할 수 있습니다: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- `lsass.exe`를 강화하기 위해 보호된 프로세스로 활성화하는 것이 권장됩니다: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

시스템 재부팅 후 검증은 보호 조치가 성공적으로 적용되었는지 확인하는 데 중요합니다. 이는 다음을 통해 달성할 수 있습니다: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## 참고 문헌
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
