# Wireshark tricks

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

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) は、企業やその顧客が **stealer malwares** によって **compromised** されているかどうかを確認するための **無料** 機能を提供する **ダークウェブ** に基づいた検索エンジンです。

WhiteIntel の主な目標は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックして、**無料** でエンジンを試すことができます:

{% embed url="https://whiteintel.io" %}

***

## Improve your Wireshark skills

### Tutorials

以下のチュートリアルは、いくつかのクールな基本的なトリックを学ぶのに素晴らしいです：

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

_**Analyze** --> **Expert Information**_ をクリックすると、パケットの **analyzed** 状態の **overview** が表示されます：

![](<../../../.gitbook/assets/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_ の下には、wireshark によって "**resolved**" されたポート/トランスポートからプロトコル、MACから製造元などのいくつかの **information** を見つけることができます。通信に関与しているものを知るのは興味深いです。

![](<../../../.gitbook/assets/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_ の下には、通信に関与する **protocols** とそれに関するデータがあります。

![](<../../../.gitbook/assets/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_ の下には、通信の **summary of the conversations** とそれに関するデータがあります。

![](<../../../.gitbook/assets/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_ の下には、通信の **summary of the endpoints** とそれぞれに関するデータがあります。

![](<../../../.gitbook/assets/image (896).png>)

**DNS info**

_**Statistics --> DNS**_ の下には、キャプチャされた DNS リクエストに関する統計があります。

![](<../../../.gitbook/assets/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_ の下には、通信の **graph** があります。

![](<../../../.gitbook/assets/image (992).png>)

### Filters

ここでは、プロトコルに応じた wireshark フィルターを見つけることができます: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
他の興味深いフィルター：

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP と初期 HTTPS トラフィック
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP と初期 HTTPS トラフィック + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP と初期 HTTPS トラフィック + TCP SYN + DNS リクエスト

### Search

セッションの **packets** 内の **content** を **search** したい場合は、_CTRL+f_ を押します。メイン情報バー (No., Time, Source など) に新しいレイヤーを追加するには、右ボタンを押してから列を編集します。

### Free pcap labs

**無料のチャレンジで練習する:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

Host HTTP ヘッダーを表示する列を追加できます：

![](<../../../.gitbook/assets/image (639).png>)

HTTPS 接続を開始する際のサーバー名を追加する列も追加できます (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identifying local hostnames

### From DHCP

現在の Wireshark では `bootp` の代わりに `DHCP` を検索する必要があります。

![](<../../../.gitbook/assets/image (1013).png>)

### From NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

サーバーとプライベートキーのすべてのデータ (_IP, Port, Protocol, Key file and password_) を追加するには、_Edit_ を押します。

### Decrypting https traffic with symmetric session keys

Firefox と Chrome の両方には、TLS セッションキーをログに記録する機能があり、これを使用して Wireshark で TLS トラフィックを復号化できます。これにより、安全な通信の詳細な分析が可能になります。この復号化を実行する方法の詳細は、[Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) のガイドにあります。

これを検出するには、環境内で変数 `SSLKEYLOGFILE` を検索します。

共有キーのファイルは次のようになります：

![](<../../../.gitbook/assets/image (820).png>)

これを wireshark にインポートするには、_edit > preference > protocol > ssl > そして (Pre)-Master-Secret log filename にインポートします：

![](<../../../.gitbook/assets/image (989).png>)

## ADB communication

APK が送信された ADB 通信から APK を抽出します：
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) は、**ダークウェブ** によって駆動される検索エンジンで、企業やその顧客が **スティーラーマルウェア** によって **侵害** されているかどうかを確認するための **無料** 機能を提供しています。

WhiteIntel の主な目標は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックして、**無料** でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWS ハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP ハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **参加する** 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**テレグラムグループ**](https://t.me/peass) に、または **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出してください。

</details>
{% endhint %}
