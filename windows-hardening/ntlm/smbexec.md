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

**Smbexec**は、Windowsシステムでのリモートコマンド実行に使用されるツールで、**Psexec**に似ていますが、ターゲットシステムに悪意のあるファイルを配置することを避けます。

### Key Points about **SMBExec**

- ターゲットマシン上に一時的なサービス（例えば、「BTOBTO」）を作成して、cmd.exe (%COMSPEC%) を介してコマンドを実行しますが、バイナリを落とすことはありません。
- ステルスなアプローチにもかかわらず、実行された各コマンドのイベントログを生成し、非対話型の「シェル」の形を提供します。
- **Smbexec**を使用して接続するためのコマンドは次のようになります:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### コマンドをバイナリなしで実行する

- **Smbexec** は、ターゲット上に物理的なバイナリが不要なサービス binPaths を通じて直接コマンドを実行することを可能にします。
- この方法は、Windows ターゲット上で一時的なコマンドを実行するのに便利です。例えば、Metasploit の `web_delivery` モジュールと組み合わせることで、PowerShell 対象のリバース Meterpreter ペイロードを実行できます。
- cmd.exe を通じて提供されたコマンドを実行するように binPath を設定したリモートサービスを攻撃者のマシン上に作成することで、ペイロードを成功裏に実行し、サービス応答エラーが発生しても Metasploit リスナーでコールバックとペイロードの実行を達成することが可能です。

### コマンドの例

サービスを作成して開始するには、以下のコマンドを使用できます：
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## 参考文献
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
