{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、ハッキングトリックを共有してください。

</details>
{% endhint %}


# Carving tools

## Autopsy

ファイルを抽出するためにフォレンジックで最も一般的に使用されるツールは[**Autopsy**](https://www.autopsy.com/download/)です。ダウンロードしてインストールし、ファイルを取り込んで「隠れた」ファイルを見つけるようにします。Autopsyはディスクイメージやその他の種類のイメージをサポートするように構築されていますが、単純なファイルには対応していません。

## Binwalk <a id="binwalk"></a>

**Binwalk**は、画像や音声ファイルなどのバイナリファイルを検索して埋め込まれたファイルやデータを見つけるためのツールです。
`apt`を使用してインストールできますが、[ソース](https://github.com/ReFirmLabs/binwalk)はgithubで見つけることができます。
**便利なコマンド**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

もう1つの一般的な隠しファイルを見つけるためのツールは**foremost**です。 foremostの設定ファイルは`/etc/foremost.conf`にあります。特定のファイルを検索したい場合は、それらのコメントを外してください。何もコメントアウトしない場合、foremostはデフォルトで構成されたファイルタイプを検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel**は、ファイルに埋め込まれたファイルを見つけて抽出するために使用できる別のツールです。この場合、抽出したいファイルタイプを設定ファイル（_/etc/scalpel/scalpel.conf_）からコメントアウトする必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

このツールはKaliに含まれていますが、こちらで見つけることができます: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

このツールは画像をスキャンし、その中に含まれる**pcapsを抽出**し、**ネットワーク情報（URL、ドメイン、IP、MAC、メール）**やさらに**ファイル**を抽出することができます。行う必要があるのは次の通りです:
```text
bulk_extractor memory.img -o out_folder
```
**ファイルデータの彫刻ツール**

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download) で入手できます。

GUI バージョンと CLI バージョンがあります。PhotoRec が検索する**ファイルタイプ**を選択できます。

![](../../../.gitbook/assets/image%20%28524%29.png)

## FindAES

AES キーを検索するためにキースケジュールを検索します。TrueCrypt や BitLocker で使用されるような 128、192、256 ビットのキーを見つけることができます。

[こちら](https://sourceforge.net/projects/findaes/) からダウンロードできます。

**補足ツール**

ターミナルから画像を表示するには [**viu** ](https://github.com/atanunq/viu)を使用できます。
PDF をテキストに変換して読むには Linux コマンドラインツール **pdftotext** を使用できます。
