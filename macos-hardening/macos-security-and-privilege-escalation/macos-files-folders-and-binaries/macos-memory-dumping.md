# macOS メモリダンプ

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


## メモリアーティファクト

### スワップファイル

スワップファイル（例：`/private/var/vm/swapfile0`）は、**物理メモリが満杯のときのキャッシュとして機能します**。物理メモリに空きがなくなると、そのデータはスワップファイルに転送され、必要に応じて物理メモリに戻されます。スワップファイルは複数存在する可能性があり、名前はswapfile0、swapfile1などとなります。

### ハイバネートイメージ

`/private/var/vm/sleepimage`にあるファイルは、**ハイバネーションモード**の際に重要です。**OS Xがハイバネートするとき、メモリのデータはこのファイルに保存されます**。コンピュータが復帰すると、システムはこのファイルからメモリデータを取得し、ユーザーは前回の作業を続けることができます。

現代のMacOSシステムでは、このファイルは通常、セキュリティ上の理由から暗号化されており、復元が難しいことに注意が必要です。

* sleepimageの暗号化が有効かどうかを確認するには、`sysctl vm.swapusage`コマンドを実行します。これにより、ファイルが暗号化されているかどうかが表示されます。

### メモリプレッシャーログ

MacOSシステムにおけるもう一つの重要なメモリ関連ファイルは、**メモリプレッシャーログ**です。これらのログは`/var/log`にあり、システムのメモリ使用状況やプレッシャーイベントに関する詳細情報を含んでいます。メモリ関連の問題を診断したり、システムが時間の経過とともにメモリをどのように管理しているかを理解するのに特に役立ちます。

## osxpmemを使用したメモリダンプ

MacOSマシンのメモリをダンプするには、[**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)を使用できます。

**注意**：以下の手順は、IntelアーキテクチャのMacにのみ適用されます。このツールは現在アーカイブされており、最後のリリースは2017年でした。以下の手順でダウンロードしたバイナリは、2017年にはApple Siliconが存在しなかったため、Intelチップを対象としています。arm64アーキテクチャ用にバイナリをコンパイルすることが可能かもしれませんが、自分で試す必要があります。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
もしこのエラーが表示された場合: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 修正するには次のようにします:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**他のエラー**は、「セキュリティとプライバシー --> 一般」で**kextの読み込みを許可する**ことで修正できるかもしれません。**許可してください**。

この**ワンライナー**を使用して、アプリケーションをダウンロードし、kextを読み込み、メモリをダンプすることもできます：

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}


{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
