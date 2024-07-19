# SmbExec/ScExec

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

## How it Works

**Smbexec**는 Windows 시스템에서 원격 명령 실행을 위해 사용되는 도구로, **Psexec**와 유사하지만 대상 시스템에 악성 파일을 배치하지 않습니다.

### Key Points about **SMBExec**

- 명령을 실행하기 위해 대상 머신에 임시 서비스(예: "BTOBTO")를 생성하여 cmd.exe (%COMSPEC%)를 통해 작동하며, 이진 파일을 드롭하지 않습니다.
- 은밀한 접근 방식에도 불구하고, 실행된 각 명령에 대한 이벤트 로그를 생성하여 비대화형 "셸"의 형태를 제공합니다.
- **Smbexec**를 사용하여 연결하는 명령은 다음과 같습니다:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### 이진 파일 없이 명령 실행하기

- **Smbexec**는 서비스 binPaths를 통해 직접 명령을 실행할 수 있게 하여, 대상에 물리적 이진 파일이 필요 없도록 합니다.
- 이 방법은 Windows 대상에서 일회성 명령을 실행하는 데 유용합니다. 예를 들어, Metasploit의 `web_delivery` 모듈과 결합하면 PowerShell을 대상으로 하는 역 Meterpreter 페이로드를 실행할 수 있습니다.
- cmd.exe를 통해 제공된 명령을 실행하도록 binPath가 설정된 원격 서비스를 공격자의 머신에서 생성함으로써, 서비스 응답 오류가 발생하더라도 페이로드를 성공적으로 실행하고 Metasploit 리스너와의 콜백 및 페이로드 실행을 달성할 수 있습니다.

### 명령 예시

서비스를 생성하고 시작하는 것은 다음 명령으로 수행할 수 있습니다:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
자세한 내용은 [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)를 확인하세요.

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

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
