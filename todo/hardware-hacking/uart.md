# UART

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

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) は、**ダークウェブ**を利用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されているかどうかを確認するための**無料**機能を提供しています。

WhiteIntelの主な目的は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトを確認し、**無料**でエンジンを試すことができます:

{% embed url="https://whiteintel.io" %}

***

## 基本情報

UARTはシリアルプロトコルであり、コンポーネント間でデータを1ビットずつ転送します。対照的に、パラレル通信プロトコルは複数のチャネルを通じてデータを同時に送信します。一般的なシリアルプロトコルには、RS-232、I2C、SPI、CAN、Ethernet、HDMI、PCI Express、USBがあります。

一般的に、UARTがアイドル状態のとき、ラインは高い状態（論理1の値）に保たれます。次に、データ転送の開始を示すために、送信者は受信者にスタートビットを送信し、その間、信号は低い状態（論理0の値）に保たれます。次に、送信者は実際のメッセージを含む5〜8ビットのデータを送信し、オプションのパリティビットと1または2のストップビット（論理1の値）を続けます。エラー検出に使用されるパリティビットは、実際にはほとんど見られません。ストップビット（またはビット）は、送信の終了を示します。

最も一般的な構成を8N1と呼びます：8ビットのデータ、パリティなし、1つのストップビット。たとえば、Cという文字、またはASCIIで0x43を8N1 UART構成で送信したい場合、次のビットを送信します：0（スタートビット）；0、1、0、0、0、0、1、1（0x43のバイナリ値）、および0（ストップビット）。

![](<../../.gitbook/assets/image (764).png>)

UARTと通信するためのハードウェアツール：

* USB-to-serialアダプタ
* CP2102またはPL2303チップを搭載したアダプタ
* Bus Pirate、Adafruit FT232H、Shikra、またはAttify Badgeなどの多目的ツール

### UARTポートの特定

UARTには4つのポートがあります：**TX**（送信）、**RX**（受信）、**Vcc**（電圧）、および**GND**（接地）。PCBに**`TX`**および**`RX`**の文字が**書かれている**4つのポートを見つけることができるかもしれません。しかし、表示がない場合は、**マルチメーター**や**ロジックアナライザー**を使用して自分で見つける必要があるかもしれません。

**マルチメーター**を使用し、デバイスの電源を切った状態で：

* **GND**ピンを特定するには、**連続性テスト**モードを使用し、黒いリードを接地に置き、赤いリードでテストしてマルチメーターから音が聞こえるまで試します。PCBには複数のGNDピンがあるため、UARTに属するものを見つけたかどうかはわかりません。
* **VCCポート**を特定するには、**DC電圧モード**を設定し、20Vの電圧に設定します。黒いプローブを接地に、赤いプローブをピンに置き、デバイスの電源を入れます。マルチメーターが3.3Vまたは5Vの一定の電圧を測定した場合、Vccピンを見つけたことになります。他の電圧が得られた場合は、他のポートで再試行します。
* **TX** **ポート**を特定するには、**DC電圧モード**を20Vに設定し、黒いプローブを接地に、赤いプローブをピンに置き、デバイスの電源を入れます。電圧が数秒間変動し、その後Vcc値で安定する場合、TXポートを見つけた可能性が高いです。これは、電源を入れるとデバッグデータを送信するためです。
* **RXポート**は他の3つに最も近く、電圧の変動が最も少なく、すべてのUARTピンの中で全体的な値が最も低いです。

TXポートとRXポートを混同しても何も起こりませんが、GNDポートとVCCポートを混同すると回路が壊れる可能性があります。

一部のターゲットデバイスでは、製造元によってRXまたはTX、または両方を無効にすることによりUARTポートが無効にされています。その場合、回路基板の接続を追跡し、ブレークアウトポイントを見つけることが役立ちます。UARTの検出がないことを確認し、回路が壊れていることを示す強い手がかりは、デバイスの保証を確認することです。デバイスが保証付きで出荷されている場合、製造元はデバッグインターフェース（この場合はUART）を残しており、したがってUARTを切断し、デバッグ中に再接続する必要があります。これらのブレークアウトピンは、はんだ付けまたはジャンパーワイヤーで接続できます。

### UARTボーレートの特定

正しいボーレートを特定する最も簡単な方法は、**TXピンの出力を見てデータを読み取る**ことです。受信したデータが読み取れない場合は、次の可能なボーレートに切り替えてデータが読み取れるようになるまで繰り返します。USB-to-serialアダプタやBus Pirateのような多目的デバイスを使用し、[baudrate.py](https://github.com/devttys0/baudrate/)のようなヘルパースクリプトと組み合わせてこれを行うことができます。最も一般的なボーレートは9600、38400、19200、57600、115200です。

{% hint style="danger" %}
このプロトコルでは、1つのデバイスのTXを他のデバイスのRXに接続する必要があることに注意することが重要です！
{% endhint %}

## CP210X UART to TTYアダプタ

CP210Xチップは、NodeMCU（esp8266を搭載）などの多くのプロトタイピングボードでシリアル通信に使用されます。これらのアダプタは比較的安価で、ターゲットのUARTインターフェースに接続するために使用できます。デバイスには5つのピンがあります：5V、GND、RXD、TXD、3.3V。ターゲットがサポートする電圧に接続して、損傷を避けるようにしてください。最後に、アダプタのRXDピンをターゲットのTXDに、アダプタのTXDピンをターゲットのRXDに接続します。

アダプタが検出されない場合は、ホストシステムにCP210Xドライバーがインストールされていることを確認してください。アダプタが検出されて接続されると、picocom、minicom、またはscreenなどのツールを使用できます。

Linux/MacOSシステムに接続されているデバイスをリストするには：
```
ls /dev/
```
UARTインターフェースとの基本的なインタラクションには、次のコマンドを使用します：
```
picocom /dev/<adapter> --baud <baudrate>
```
minicomの設定には、次のコマンドを使用します：
```
minicom -s
```
設定を`Serial port setup`オプションでボーレートやデバイス名などに構成します。

構成後、`minicom`コマンドを使用してUARTコンソールを開始します。

## Arduino UNO R3を介したUART（取り外し可能なAtmel 328pチップボード）

UARTシリアルからUSBアダプタが利用できない場合、Arduino UNO R3を使って簡単なハックを行うことができます。Arduino UNO R3は通常どこでも入手可能なため、これにより多くの時間を節約できます。

Arduino UNO R3には、ボード自体にUSBからシリアルへのアダプタが組み込まれています。UART接続を得るには、ボードからAtmel 328pマイクロコントローラーチップを抜き出すだけです。このハックは、Atmel 328pがボードにハンダ付けされていないArduino UNO R3のバリアント（SMDバージョンが使用されています）で機能します。ArduinoのRXピン（デジタルピン0）をUARTインターフェースのTXピンに接続し、ArduinoのTXピン（デジタルピン1）をUARTインターフェースのRXピンに接続します。

最後に、シリアルコンソールを取得するためにArduino IDEを使用することをお勧めします。メニューの`tools`セクションで`Serial Console`オプションを選択し、UARTインターフェースに応じてボーレートを設定します。

## Bus Pirate

このシナリオでは、プログラムのすべての印刷をシリアルモニターに送信しているArduinoのUART通信をスニッフィングします。
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## Dumping Firmware with UART Console

UART Consoleは、ランタイム環境で基盤となるファームウェアを操作するための優れた方法を提供します。しかし、UART Consoleのアクセスが読み取り専用の場合、多くの制約が生じる可能性があります。多くの組み込みデバイスでは、ファームウェアはEEPROMに保存され、揮発性メモリを持つプロセッサで実行されます。したがって、元のファームウェアは製造時にEEPROM自体にあり、新しいファイルは揮発性メモリのために失われるため、ファームウェアは読み取り専用のまま保持されます。したがって、組み込みファームウェアを扱う際にファームウェアをダンプすることは貴重な努力です。

これを行う方法はいくつかあり、SPIセクションではさまざまなデバイスを使用してEEPROMから直接ファームウェアを抽出する方法を説明しています。ただし、物理デバイスや外部インタラクションを使用してファームウェアをダンプすることはリスクがあるため、最初にUARTを使用してファームウェアをダンプすることをお勧めします。

UART Consoleからファームウェアをダンプするには、まずブートローダーにアクセスする必要があります。多くの人気ベンダーは、Linuxをロードするためのブートローダーとしてuboot（Universal Bootloader）を使用しています。したがって、ubootにアクセスすることが必要です。

ブートローダーにアクセスするには、UARTポートをコンピュータに接続し、任意のシリアルコンソールツールを使用し、デバイスへの電源供給を切断しておきます。セットアップが完了したら、Enterキーを押して保持します。最後に、デバイスに電源を接続し、ブートさせます。

これを行うことで、ubootのロードが中断され、メニューが表示されます。ubootコマンドを理解し、ヘルプメニューを使用してそれらをリストすることをお勧めします。これが`help`コマンドかもしれません。異なるベンダーが異なる構成を使用しているため、それぞれを個別に理解することが必要です。

通常、ファームウェアをダンプするためのコマンドは：
```
md
```
which stands for "memory dump". これはメモリ（EEPROMコンテンツ）を画面にダンプします。メモリダンプをキャプチャするために、手順を開始する前にシリアルコンソールの出力をログに記録することをお勧めします。

最後に、ログファイルから不要なデータをすべて削除し、ファイルを `filename.rom` として保存し、binwalkを使用して内容を抽出します:
```
binwalk -e <filename.rom>
```
これは、16進数ファイルに見つかった署名に従って、EEPROMからの可能な内容をリストします。

ただし、使用されている場合でも、ubootが常にロック解除されているわけではないことに注意する必要があります。Enterキーが何も反応しない場合は、Spaceキーなどの異なるキーを確認してください。ブートローダーがロックされていて中断されない場合、この方法は機能しません。デバイスのブートローダーがubootであるかどうかを確認するには、デバイスのブート中にUARTコンソールの出力を確認してください。ブート中にubootと表示されるかもしれません。

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**に基づいた検索エンジンで、企業やその顧客が**スティーラーマルウェア**によって**侵害された**かどうかを確認するための**無料**機能を提供しています。

WhiteIntelの主な目標は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトを確認し、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
