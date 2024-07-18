# Android Forensics

{% hint style="success" %}
**AWSハッキングの学習と練習:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**GCPハッキングの学習と練習:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して**ハッキングテクニックを共有**してください。

</details>
{% endhint %}

## ロックされたデバイス

Androidデバイスからデータを抽出するには、デバイスをアンロックする必要があります。ロックされている場合は以下を試すことができます:

* USB経由のデバッグが有効かどうかを確認します。
* 可能な[指紋攻撃](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)をチェックします。
* [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)を試してみます。

## データ取得

[adbを使用してAndroidバックアップを作成](mobile-pentesting/android-app-pentesting/adb-commands.md#backup)し、[Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)を使用して抽出します: `java -jar abe.jar unpack file.backup file.tar`

### ルートアクセスまたはJTAGインターフェースへの物理的接続がある場合

* `cat /proc/partitions`（フラッシュメモリへのパスを検索します。一般的に最初のエントリは_mmcblk0_であり、フラッシュメモリ全体に対応します）。
* `df /data`（システムのブロックサイズを発見します）。
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096（ブロックサイズから収集した情報を使用して実行します）。

### メモリ

Linux Memory Extractor（LiME）を使用してRAM情報を抽出します。これはadb経由でロードする必要があるカーネル拡張機能です。

{% hint style="success" %}
**AWSハッキングの学習と練習:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**GCPハッキングの学習と練習:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して**ハッキングテクニックを共有**してください。

</details>
{% endhint %}
