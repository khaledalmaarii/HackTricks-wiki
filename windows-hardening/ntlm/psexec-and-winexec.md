# PsExec/Winexec/ScExec

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>로부터 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 작동 방식

서비스 이진 파일을 조작하여 SMB를 통해 대상 컴퓨터에서 원격 실행을 달성하는 과정은 다음과 같은 단계로 설명됩니다:

1. SMB를 통해 **ADMIN$ 공유로 서비스 이진 파일 복사**가 수행됩니다.
2. 원격 컴퓨터에 **서비스 생성**이 이루어집니다. 생성된 서비스는 해당 이진 파일을 가리킵니다.
3. 서비스가 **원격으로 시작**됩니다.
4. 종료 시, 서비스가 **중지되고 이진 파일이 삭제**됩니다.

### **PsExec 수동 실행 과정**

msfvenom으로 생성되고 Veil을 사용하여 백신 탐지를 회피하기 위해 난독화된 실행 페이로드인 'met8888.exe'가 있다고 가정하면, 다음 단계를 수행합니다:

- **이진 파일 복사**: 명령 프롬프트에서 실행 파일을 ADMIN$ 공유로 복사하지만 숨겨지기 위해 파일 시스템의 어느 곳에나 배치할 수 있습니다.

- **서비스 생성**: Windows `sc` 명령을 사용하여 원격으로 Windows 서비스를 조회, 생성 및 삭제할 수 있으며, 업로드된 이진 파일을 가리키는 "meterpreter"라는 서비스가 생성됩니다.

- **서비스 시작**: 마지막 단계는 서비스를 시작하는 것으로, 이진 파일이 실제 서비스 이진 파일이 아니기 때문에 예상된 응답 코드를 반환하지 못하고 "시간 초과" 오류가 발생할 가능성이 높습니다. 이 오류는 이진 파일의 실행이 주된 목표이므로 중요하지 않습니다.

Metasploit 리스너를 관찰하면 세션이 성공적으로 시작된 것을 확인할 수 있습니다.

[`sc` 명령에 대해 더 알아보기](https://technet.microsoft.com/en-us/library/bb490995.aspx).

자세한 단계는 다음에서 확인할 수 있습니다: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**또한 Windows Sysinternals 이진 파일 PsExec.exe를 사용할 수 있습니다:**

![](<../../.gitbook/assets/image (165).png>)

[**SharpLateral**](https://github.com/mertdas/SharpLateral)도 사용할 수 있습니다:

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
