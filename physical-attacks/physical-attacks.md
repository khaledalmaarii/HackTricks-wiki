# 物理攻撃

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してハッキングトリックを共有してください。**

</details>
{% endhint %}

## BIOSパスワードの回復とシステムセキュリティ

**BIOSのリセット**は、いくつかの方法で実行できます。ほとんどのマザーボードには**バッテリー**が含まれており、これを約**30分**取り外すことで、パスワードを含むBIOS設定がリセットされます。あるいは、**マザーボード上のジャンパー**を調整して、特定のピンを接続することでこれらの設定をリセットできます。

ハードウェアの調整が不可能または実用的でない場合、**ソフトウェアツール**が解決策を提供します。**Kali Linux**のようなディストリビューションを使用して**Live CD/USB**からシステムを起動すると、BIOSパスワードの回復を支援する**_killCmos_**や**_CmosPWD_**のようなツールにアクセスできます。

BIOSパスワードが不明な場合、誤って**3回**入力すると、通常はエラーコードが表示されます。このコードは、[https://bios-pw.org](https://bios-pw.org)のようなウェブサイトで使用して、使用可能なパスワードを取得するのに役立ちます。

### UEFIセキュリティ

従来のBIOSの代わりに**UEFI**を使用している現代のシステムでは、ツール**chipsec**を使用してUEFI設定を分析および変更し、**Secure Boot**を無効にすることができます。これは、次のコマンドで実行できます：

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM分析とコールドブート攻撃

RAMは、電源が切れた後もデータを短時間保持します。通常は**1〜2分**ですが、液体窒素のような冷却物質を適用することで**10分**に延長できます。この延長された期間中に、**dd.exe**や**volatility**のようなツールを使用して**メモリダンプ**を作成し、分析できます。

### 直接メモリアクセス（DMA）攻撃

**INCEPTION**は、**DMA**を介して**物理メモリ操作**を行うために設計されたツールで、**FireWire**や**Thunderbolt**のようなインターフェースと互換性があります。これは、任意のパスワードを受け入れるようにメモリをパッチすることでログイン手続きをバイパスできます。ただし、**Windows 10**システムには効果がありません。

### システムアクセスのためのLive CD/USB

**_sethc.exe_**や**_Utilman.exe_**のようなシステムバイナリを**_cmd.exe_**のコピーで変更することで、システム権限を持つコマンドプロンプトを提供できます。**chntpw**のようなツールを使用して、Windowsインストールの**SAM**ファイルを編集し、パスワードを変更できます。

**Kon-Boot**は、WindowsカーネルまたはUEFIを一時的に変更することで、パスワードを知らなくてもWindowsシステムにログインできるツールです。詳細は[https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)で確認できます。

### Windowsセキュリティ機能の取り扱い

#### ブートおよびリカバリーショートカット

- **Supr**: BIOS設定にアクセス。
- **F8**: リカバリーモードに入る。
- Windowsバナーの後に**Shift**を押すことで、自動ログインをバイパスできます。

#### BAD USBデバイス

**Rubber Ducky**や**Teensyduino**のようなデバイスは、ターゲットコンピュータに接続されたときに事前定義されたペイロードを実行できる**bad USB**デバイスを作成するためのプラットフォームとして機能します。

#### ボリュームシャドウコピー

管理者権限を持つことで、PowerShellを通じて**SAM**ファイルを含む機密ファイルのコピーを作成できます。

### BitLocker暗号化のバイパス

BitLocker暗号化は、**MEMORY.DMP**ファイル内に**リカバリーパスワード**が見つかればバイパスできる可能性があります。これには、**Elcomsoft Forensic Disk Decryptor**や**Passware Kit Forensic**のようなツールを使用できます。

### リカバリーキー追加のためのソーシャルエンジニアリング

新しいBitLockerリカバリーキーは、ユーザーに新しいリカバリーキーをゼロで構成するコマンドを実行させることで追加でき、これにより復号化プロセスが簡素化されます。

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してハッキングトリックを共有してください。**

</details>
{% endhint %}
