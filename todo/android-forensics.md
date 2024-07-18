# Android Forensics

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

## ロックされたデバイス

Androidデバイスからデータを抽出するには、デバイスがロック解除されている必要があります。ロックされている場合は、次のことを行うことができます：

* デバイスでUSB経由のデバッグが有効になっているか確認する。
* 可能な[スムッジ攻撃](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)を確認する。
* [ブルートフォース](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)を試みる。

## データ取得

[adbを使用してandroidバックアップを作成](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup)し、[Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)を使用して抽出します：`java -jar abe.jar unpack file.backup file.tar`

### rootアクセスまたはJTAGインターフェースへの物理接続がある場合

* `cat /proc/partitions`（フラッシュメモリへのパスを検索します。一般的に最初のエントリは _mmcblk0_ で、全体のフラッシュメモリに対応します）。
* `df /data`（システムのブロックサイズを発見します）。
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096（ブロックサイズから収集した情報を使用して実行します）。

### メモリ

Linux Memory Extractor (LiME)を使用してRAM情報を抽出します。これは、adb経由でロードする必要があるカーネル拡張です。

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
