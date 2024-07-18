# macOSメモリーダンピング

{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出してハッキングテクニックを共有してください。

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックする**無料**の機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

***

## メモリーアーティファクト

### スワップファイル

`/private/var/vm/swapfile0`などのスワップファイルは、物理メモリがいっぱいのときに**キャッシュとして機能**します。物理メモリにもう余裕がない場合、そのデータはスワップファイルに転送され、必要に応じて物理メモリに戻されます。swapfile0、swapfile1などの名前の複数のスワップファイルが存在する可能性があります。

### ハイバネーションイメージ

`/private/var/vm/sleepimage`にあるファイルは、**ハイバネーションモード**中に重要です。OS Xが休止状態に入るとき、**メモリからのデータはこのファイルに保存**されます。コンピューターを起動すると、システムはこのファイルからメモリデータを取得して、ユーザーが前回終了したところから続行できるようにします。

現代のMacOSシステムでは、セキュリティ上の理由からこのファイルが通常暗号化されているため、回復が難しいことに注意してください。

* sleepimageの暗号化が有効かどうかを確認するには、`sysctl vm.swapusage`コマンドを実行します。これにより、ファイルが暗号化されているかどうかが表示されます。

### メモリープレッシャーログ

MacOSシステムにおけるもう1つの重要なメモリ関連ファイルは**メモリープレッシャーログ**です。これらのログは`/var/log`にあり、システムのメモリ使用状況やプレッシャーイベントに関する詳細な情報を含んでいます。これらは、メモリ関連の問題の診断やシステムが時間の経過とともにメモリをどのように管理しているかを理解するのに特に役立ちます。

## osxpmemを使用したメモリーダンプ

MacOSマシンでメモリをダンプするためには、[**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)を使用できます。

**注意**: 以下の手順は、Intelアーキテクチャを持つMacにのみ適用されます。このツールは現在アーカイブされており、最後のリリースは2017年に行われました。以下の手順でダウンロードしたバイナリは、Apple Siliconが2017年には存在しなかったため、Intelチップをターゲットにしています。arm64アーキテクチャ向けにバイナリをコンパイルすることも可能かもしれませんが、自分で試してみる必要があります。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
もし次のエラーが見つかった場合：`osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 以下の手順で修正できます：
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**その他のエラー**は、「セキュリティとプライバシー --> 一般」で**kextの読み込みを許可**することで修正できるかもしれません。単に**許可**してください。

また、次の**ワンライナー**を使用してアプリケーションをダウンロードし、kextをロードしてメモリをダンプすることもできます:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックする**無料**の機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックし、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWSハッキングの学習と実践：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、ハッキングトリックを共有してください。

</details>
{% endhint %}
