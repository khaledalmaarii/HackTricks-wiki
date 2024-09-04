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


## Improve your Wireshark skills

### Tutorials

以下のチュートリアルは、いくつかのクールな基本的なトリックを学ぶのに素晴らしいです：

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

_**Analyze** --> **Expert Information**_をクリックすると、**分析された**パケットで何が起こっているかの**概要**が得られます：

![](<../../../.gitbook/assets/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_の下には、wiresharkによって「**解決された**」いくつかの**情報**（ポート/トランスポートからプロトコル、MACから製造元など）を見つけることができます。通信に関与しているものを知ることは興味深いです。

![](<../../../.gitbook/assets/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_の下には、通信に関与する**プロトコル**とそれに関するデータがあります。

![](<../../../.gitbook/assets/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_の下には、通信の**会話の概要**とそれに関するデータがあります。

![](<../../../.gitbook/assets/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_の下には、通信の**エンドポイントの概要**とそれぞれに関するデータがあります。

![](<../../../.gitbook/assets/image (896).png>)

**DNS info**

_**Statistics --> DNS**_の下には、キャプチャされたDNSリクエストに関する統計があります。

![](<../../../.gitbook/assets/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_の下には、**通信のグラフ**があります。

![](<../../../.gitbook/assets/image (992).png>)

### Filters

ここでは、プロトコルに応じたwiresharkフィルターを見つけることができます：[https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
他の興味深いフィルター：

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTPおよび初期HTTPSトラフィック
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTPおよび初期HTTPSトラフィック + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTPおよび初期HTTPSトラフィック + TCP SYN + DNSリクエスト

### Search

セッションの**パケット**内の**コンテンツ**を**検索**したい場合は、_CTRL+f_を押します。メイン情報バー（No.、Time、Sourceなど）に新しいレイヤーを追加するには、右ボタンを押してから列を編集します。

### Free pcap labs

**無料のチャレンジで練習する：** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

Host HTTPヘッダーを表示する列を追加できます：

![](<../../../.gitbook/assets/image (639).png>)

そして、開始HTTPS接続からサーバー名を追加する列（**ssl.handshake.type == 1**）：

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identifying local hostnames

### From DHCP

現在のWiresharkでは、`bootp`の代わりに`DHCP`を検索する必要があります。

![](<../../../.gitbook/assets/image (1013).png>)

### From NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

_サーバーとプライベートキーのすべてのデータを追加するには、_Edit_を押します（_IP、Port、Protocol、Key fileおよびpassword_）

### Decrypting https traffic with symmetric session keys

FirefoxとChromeの両方は、TLSセッションキーをログに記録する機能があり、これを使用してWiresharkでTLSトラフィックを復号化できます。これにより、安全な通信の詳細な分析が可能になります。この復号化を実行する方法の詳細は、[Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)のガイドにあります。

これを検出するには、環境内で変数`SSLKEYLOGFILE`を検索します。

共有キーのファイルは次のようになります：

![](<../../../.gitbook/assets/image (820).png>)

これをwiresharkにインポートするには、_edit > preference > protocol > ssl >_に移動し、(Pre)-Master-Secretログファイル名にインポートします：

![](<../../../.gitbook/assets/image (989).png>)

## ADB communication

APKが送信されたADB通信からAPKを抽出します：
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
{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
