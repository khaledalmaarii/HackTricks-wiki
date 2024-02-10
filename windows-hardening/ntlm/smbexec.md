# SmbExec/ScExec

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 작동 방식

**Smbexec**은 Windows 시스템에서 원격 명령 실행에 사용되는 도구로, **Psexec**와 유사하지만 대상 시스템에 악성 파일을 배치하지 않습니다.

### **SMBExec**에 대한 주요 사항

- 명령을 실행하기 위해 대상 시스템에 임시 서비스 (예: "BTOBTO")를 생성하여 cmd.exe (%COMSPEC%)를 통해 명령을 실행하며, 바이너리를 드롭하지 않습니다.
- 은밀한 접근 방식에도 불구하고, 각 명령 실행에 대한 이벤트 로그를 생성하여 비대화식 "셸"을 제공합니다.
- **Smbexec**을 사용하여 연결하는 명령은 다음과 같습니다:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### 이진 파일 없이 명령 실행하기

- **Smbexec**은 대상에 대한 물리적인 이진 파일이 필요 없이 서비스 binPaths를 통해 직접 명령을 실행할 수 있게 해줍니다.
- 이 방법은 Windows 대상에 대해 일회성 명령을 실행하는 데 유용합니다. 예를 들어, Metasploit의 `web_delivery` 모듈과 함께 사용하면 PowerShell을 대상으로 한 역방향 Meterpreter 페이로드를 실행할 수 있습니다.
- 공격자의 기계에서 binPath를 설정하여 제공된 명령을 cmd.exe를 통해 실행하는 원격 서비스를 생성하면, 서비스 응답 오류가 발생하더라도 Metasploit 리스너를 통해 콜백 및 페이로드 실행을 성공적으로 달성할 수 있습니다.

### 명령 예시

다음 명령을 사용하여 서비스를 생성하고 시작할 수 있습니다:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
자세한 내용은 [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)를 확인하세요.


## 참고 자료
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
