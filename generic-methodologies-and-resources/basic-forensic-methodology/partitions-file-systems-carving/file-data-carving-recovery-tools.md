# ファイル/データカービングと回復ツール

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}

## カービングと回復ツール

[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)にもっと多くのツールがあります。

### Autopsy

画像からファイルを抽出するためにフォレンジックで最も一般的に使用されるツールは[**Autopsy**](https://www.autopsy.com/download/)です。ダウンロードしてインストールし、ファイルを取り込んで「隠れた」ファイルを見つけます。Autopsyはディスクイメージや他の種類のイメージをサポートするように構築されていますが、単純なファイルには対応していないことに注意してください。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**は、埋め込まれたコンテンツを見つけるためにバイナリファイルを分析するツールです。`apt`を介してインストール可能で、そのソースは[GitHub](https://github.com/ReFirmLabs/binwalk)にあります。

**便利なコマンド**：
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

もう一つの一般的なツールは**foremost**です。foremostの設定ファイルは`/etc/foremost.conf`にあります。特定のファイルを検索したい場合は、それらのコメントを外してください。何もコメントを外さなければ、foremostはデフォルトで設定されたファイルタイプを検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**は、**ファイルに埋め込まれたファイル**を見つけて抽出するために使用できる別のツールです。この場合、抽出したいファイルタイプを設定ファイル(_/etc/scalpel/scalpel.conf_)からコメント解除する必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

このツールはKaliに含まれていますが、こちらでも見つけることができます: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

このツールはイメージをスキャンし、その中にある**pcaps**、**ネットワーク情報（URL、ドメイン、IP、MAC、メール）**、およびその他の**ファイル**を**抽出**します。あなたがする必要があるのは:
```
bulk_extractor memory.img -o out_folder
```
すべての情報をナビゲートします（パスワード？）、パケットを分析します（[**Pcaps分析**](../pcap-inspection/)を読む）、奇妙なドメインを検索します（**マルウェア**や**存在しない**ドメインに関連する）。

### PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)で見つけることができます。

GUIとCLIのバージョンがあります。PhotoRecが検索する**ファイルタイプ**を選択できます。

![](<../../../.gitbook/assets/image (242).png>)

### binvis

[コード](https://code.google.com/archive/p/binvis/)と[ウェブページツール](https://binvis.io/#/)を確認してください。

#### BinVisの特徴

* 視覚的でアクティブな**構造ビューワー**
* 異なる焦点のための複数のプロット
* サンプルの一部に焦点を当てる
* PEまたはELF実行可能ファイルの**文字列とリソース**を見る
* ファイルの暗号解析のための**パターン**を取得
* パッカーやエンコーダアルゴリズムを**特定**
* パターンによるステガノグラフィの**識別**
* **視覚的**なバイナリ差分

BinVisは、ブラックボックスシナリオで未知のターゲットに慣れるための素晴らしい**出発点**です。

## 特定のデータカービングツール

### FindAES

AESキーのスケジュールを検索することでAESキーを検索します。TrueCryptやBitLockerで使用される128、192、256ビットのキーを見つけることができます。

[こちらからダウンロード](https://sourceforge.net/projects/findaes/)。

## 補完ツール

[**viu**](https://github.com/atanunq/viu)を使用してターミナルから画像を見ることができます。\
Linuxコマンドラインツール**pdftotext**を使用してPDFをテキストに変換し、読むことができます。

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
