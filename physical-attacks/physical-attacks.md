# 物理攻撃

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

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を利用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されているかどうかを確認するための**無料**機能を提供しています。

WhiteIntelの主な目標は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトを確認し、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

---

## BIOSパスワードの回復とシステムセキュリティ

**BIOSのリセット**は、いくつかの方法で実行できます。ほとんどのマザーボードには**バッテリー**が含まれており、約**30分**取り外すことで、パスワードを含むBIOS設定がリセットされます。あるいは、**マザーボード上のジャンパー**を調整して、特定のピンを接続することでこれらの設定をリセットできます。

ハードウェアの調整が不可能または実用的でない場合、**ソフトウェアツール**が解決策を提供します。**Kali Linux**のようなディストリビューションを使用して**Live CD/USB**からシステムを実行することで、BIOSパスワードの回復を支援する**_killCmos_**や**_CmosPWD_**などのツールにアクセスできます。

BIOSパスワードが不明な場合、誤って**3回**入力すると、通常はエラーコードが表示されます。このコードは、[https://bios-pw.org](https://bios-pw.org)のようなウェブサイトで使用して、使用可能なパスワードを取得することができます。

### UEFIセキュリティ

従来のBIOSの代わりに**UEFI**を使用する現代のシステムでは、**chipsec**ツールを利用してUEFI設定を分析および変更し、**Secure Boot**を無効にすることができます。これは次のコマンドで実行できます：

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM分析とコールドブート攻撃

RAMは電源が切れた後、通常**1〜2分**間データを保持します。この持続性は、液体窒素などの冷却物質を適用することで**10分**に延長できます。この延長された期間中に、**dd.exe**や**volatility**などのツールを使用してメモリダンプを作成し、分析することができます。

### ダイレクトメモリアクセス（DMA）攻撃

**INCEPTION**は、**物理メモリ操作**のために設計されたツールで、**FireWire**や**Thunderbolt**のようなインターフェースと互換性があります。これは、任意のパスワードを受け入れるようにメモリをパッチすることでログイン手続きをバイパスすることを可能にします。ただし、**Windows 10**システムには効果がありません。

### システムアクセスのためのLive CD/USB

**_sethc.exe_**や**_Utilman.exe_**のようなシステムバイナリを**_cmd.exe_**のコピーで変更することで、システム権限を持つコマンドプロンプトを提供できます。**chntpw**のようなツールを使用して、Windowsインストールの**SAM**ファイルを編集し、パスワードを変更することができます。

**Kon-Boot**は、WindowsカーネルやUEFIを一時的に変更することで、パスワードを知らなくてもWindowsシステムにログインすることを容易にするツールです。詳細情報は[https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)で確認できます。

### Windowsセキュリティ機能の取り扱い

#### ブートおよびリカバリーショートカット

- **Supr**：BIOS設定にアクセス。
- **F8**：リカバリーモードに入る。
- Windowsバナーの後に**Shift**を押すことで、自動ログインをバイパスできます。

#### BAD USBデバイス

**Rubber Ducky**や**Teensyduino**のようなデバイスは、ターゲットコンピュータに接続されたときに事前定義されたペイロードを実行できる**bad USB**デバイスを作成するためのプラットフォームとして機能します。

#### ボリュームシャドウコピー

管理者権限を持つことで、PowerShellを通じて**SAM**ファイルを含む機密ファイルのコピーを作成できます。

### BitLocker暗号化のバイパス

BitLocker暗号化は、**回復パスワード**がメモリダンプファイル（**MEMORY.DMP**）内に見つかる場合、バイパスされる可能性があります。これには、**Elcomsoft Forensic Disk Decryptor**や**Passware Kit Forensic**のようなツールを利用できます。

### 回復キー追加のためのソーシャルエンジニアリング

新しいBitLocker回復キーは、ユーザーに新しい回復キーをゼロで構成するコマンドを実行させることで追加でき、これにより復号化プロセスが簡素化されます。

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を利用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されているかどうかを確認するための**無料**機能を提供しています。

WhiteIntelの主な目標は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトを確認し、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

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
