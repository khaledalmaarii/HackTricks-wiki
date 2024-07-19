# ハードウェアハッキング

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}

## JTAG

JTAGは境界スキャンを実行することを可能にします。境界スキャンは、埋め込まれた境界スキャンセルや各ピンのレジスタを含む特定の回路を分析します。

JTAG標準は、以下を含む**境界スキャンを実施するための特定のコマンド**を定義しています：

* **BYPASS**は、他のチップを通過するオーバーヘッドなしで特定のチップをテストすることを可能にします。
* **SAMPLE/PRELOAD**は、デバイスが通常の動作モードにあるときに出入りするデータのサンプルを取得します。
* **EXTEST**は、ピンの状態を設定および読み取ります。

他にも以下のようなコマンドをサポートしています：

* **IDCODE**はデバイスを識別するためのもの
* **INTEST**はデバイスの内部テスト用

JTAGulatorのようなツールを使用すると、これらの命令に出くわすことがあります。

### テストアクセスポート

境界スキャンには、一般的なポートである**テストアクセスポート（TAP）**の4線テストが含まれ、コンポーネントに組み込まれた**JTAGテストサポート**機能へのアクセスを提供します。TAPは以下の5つの信号を使用します：

* テストクロック入力（**TCK**）TCKは、TAPコントローラーが単一のアクションを実行する頻度を定義する**クロック**です（言い換えれば、状態マシンの次の状態にジャンプします）。
* テストモード選択（**TMS**）入力TMSは**有限状態機械**を制御します。クロックの各ビートで、デバイスのJTAG TAPコントローラーはTMSピンの電圧をチェックします。電圧が特定の閾値を下回ると、信号は低と見なされ0として解釈され、電圧が特定の閾値を上回ると、信号は高と見なされ1として解釈されます。
* テストデータ入力（**TDI**）TDIは、**スキャンセルを通じてチップにデータを送信する**ピンです。JTAGはこのピンを介した通信プロトコルを定義していないため、各ベンダーがこのピンの通信プロトコルを定義する責任があります。
* テストデータ出力（**TDO**）TDOは、**チップからデータを送信する**ピンです。
* テストリセット（**TRST**）入力オプションのTRSTは、有限状態機械を**既知の良好な状態**にリセットします。あるいは、TMSが5回連続して1に保持されると、TRSTピンと同様にリセットが呼び出されるため、TRSTはオプションです。

時には、PCBにマークされたこれらのピンを見つけることができるでしょう。他の場合には、**それらを見つける必要があるかもしれません**。

### JTAGピンの特定

JTAGポートを検出する最も速いが最も高価な方法は、**JTAGulator**を使用することです。このデバイスはこの目的のために特別に作成されました（ただし、**UARTピンアウトも検出できます**）。

それは**24チャンネル**を持ち、ボードのピンに接続できます。その後、すべての可能な組み合わせの**BF攻撃**を実行し、**IDCODE**および**BYPASS**境界スキャンコマンドを送信します。応答を受け取ると、各JTAG信号に対応するチャンネルを表示します。

JTAGピンアウトを特定するためのより安価だがはるかに遅い方法は、Arduino互換のマイクロコントローラーにロードされた[**JTAGenum**](https://github.com/cyphunk/JTAGenum/)を使用することです。

**JTAGenum**を使用する場合、最初に列挙に使用するプロービングデバイスのピンを**定義**する必要があります。デバイスのピンアウト図を参照し、これらのピンをターゲットデバイスのテストポイントに接続する必要があります。

JTAGピンを特定する**第三の方法**は、**PCBを検査**してピンアウトの1つを探すことです。場合によっては、PCBが便利に**Tag-Connectインターフェース**を提供していることがあり、これはボードにJTAGコネクタがある明確な兆候です。そのインターフェースがどのように見えるかは[https://www.tag-connect.com/info/](https://www.tag-connect.com/info/)で確認できます。さらに、PCB上のチップセットの**データシートを検査する**ことで、JTAGインターフェースを指し示すピンアウト図が明らかになるかもしれません。

## SDW

SWDはデバッグ用に設計されたARM特有のプロトコルです。

SWDインターフェースは**2つのピン**を必要とします：双方向の**SWDIO**信号、これはJTAGの**TDIおよびTDOピン**に相当し、クロックである**SWCLK**、これはJTAGの**TCK**に相当します。多くのデバイスは、ターゲットにSWDまたはJTAGプローブを接続できる**シリアルワイヤまたはJTAGデバッグポート（SWJ-DP）**をサポートしています。

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
