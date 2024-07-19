# SPI

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

## 基本情報

SPI（シリアルペリフェラルインターフェース）は、IC（集積回路）間の短距離通信に使用される同期シリアル通信プロトコルです。SPI通信プロトコルは、クロックとチップセレクト信号によって調整されるマスター-スレーブアーキテクチャを利用します。マスター-スレーブアーキテクチャは、EEPROM、センサー、制御デバイスなどの外部周辺機器を管理するマスター（通常はマイクロプロセッサ）で構成され、これらはスレーブと見なされます。

複数のスレーブがマスターに接続できますが、スレーブ同士は通信できません。スレーブは、クロックとチップセレクトの2つのピンによって管理されます。SPIは同期通信プロトコルであるため、入力ピンと出力ピンはクロック信号に従います。チップセレクトは、マスターがスレーブを選択して相互作用するために使用されます。チップセレクトが高いと、スレーブデバイスは選択されず、低いと、チップが選択され、マスターがスレーブと相互作用します。

MOSI（マスターアウト、スレーブイン）とMISO（マスターイン、スレーブアウト）は、データの送信と受信を担当します。データは、MOSIピンを通じてスレーブデバイスに送信され、チップセレクトが低く保たれます。入力データには、スレーブデバイスベンダーのデータシートに従った命令、メモリアドレス、またはデータが含まれます。有効な入力があると、MISOピンはマスターにデータを送信します。出力データは、入力が終了した次のクロックサイクルで送信されます。MISOピンは、データが完全に送信されるまで、またはマスターがチップセレクトピンを高く設定するまでデータを送信します（その場合、スレーブは送信を停止し、マスターはその後のクロックサイクルで聞き取らなくなります）。

## EEPROMからのファームウェアのダンプ

ファームウェアのダンプは、ファームウェアを分析し、脆弱性を見つけるのに役立ちます。多くの場合、ファームウェアはインターネット上で入手できないか、モデル番号、バージョンなどの要因の変動により無関係です。したがって、物理デバイスから直接ファームウェアを抽出することは、脅威を特定する際に役立ちます。

シリアルコンソールを取得することは役立ちますが、ファイルが読み取り専用であることがよくあります。これにより、さまざまな理由から分析が制約されます。たとえば、パッケージを送受信するために必要なツールがファームウェアに存在しない場合があります。したがって、バイナリを抽出して逆アセンブルすることは実行可能ではありません。したがって、システムにファームウェア全体をダンプし、分析のためにバイナリを抽出することは非常に役立ちます。

また、レッドチーミング中やデバイスへの物理アクセスを取得する際に、ファームウェアをダンプすることでファイルを変更したり、悪意のあるファイルを注入したりして、それをメモリに再フラッシュすることができ、デバイスにバックドアを埋め込むのに役立ちます。したがって、ファームウェアのダンプによって解放される可能性は無数にあります。

### CH341A EEPROMプログラマーおよびリーダー

このデバイスは、EEPROMからファームウェアをダンプし、ファームウェアファイルで再フラッシュするための手頃なツールです。これは、コンピュータのBIOSチップ（実際にはEEPROM）で作業するための人気の選択肢です。このデバイスはUSB経由で接続され、開始するために最小限のツールが必要です。また、通常は迅速に作業を完了するため、物理デバイスへのアクセスにも役立ちます。

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

EEPROMメモリをCH341aプログラマーに接続し、デバイスをコンピュータに接続します。デバイスが検出されない場合は、コンピュータにドライバーをインストールしてみてください。また、EEPROMが正しい向きで接続されていることを確認してください（通常、VCCピンをUSBコネクタに対して逆向きに配置します）。そうしないと、ソフトウェアがチップを検出できません。必要に応じて図を参照してください：

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

最後に、flashrom、G-Flash（GUI）などのソフトウェアを使用してファームウェアをダンプします。G-Flashは、最小限のGUIツールで、迅速でEEPROMを自動的に検出します。これは、ファームウェアを迅速に抽出する必要がある場合に役立ち、文書をあまりいじることなく使用できます。

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

ファームウェアをダンプした後、バイナリファイルの分析を行うことができます。strings、hexdump、xxd、binwalkなどのツールを使用して、ファームウェアやファイルシステム全体に関する多くの情報を抽出できます。

ファームウェアからの内容を抽出するには、binwalkを使用できます。Binwalkは、16進数の署名を分析し、バイナリファイル内のファイルを特定し、それらを抽出することができます。
```
binwalk -e <filename>
```
The can be .bin or .rom as per the tools and configurations used.

{% hint style="danger" %}
ファームウェアの抽出は繊細なプロセスであり、多くの忍耐が必要です。取り扱いを誤ると、ファームウェアが破損したり、完全に消去されてデバイスが使用できなくなる可能性があります。ファームウェアを抽出する前に、特定のデバイスを研究することをお勧めします。
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Pirate BusのPINOUTがSPIに接続するための**MOSI**および**MISO**のピンを示していても、いくつかのSPIはピンをDIおよびDOとして示す場合があります。**MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

WindowsまたはLinuxでは、プログラム[**`flashrom`**](https://www.flashrom.org/Flashrom)を使用して、次のようにフラッシュメモリの内容をダンプできます:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
