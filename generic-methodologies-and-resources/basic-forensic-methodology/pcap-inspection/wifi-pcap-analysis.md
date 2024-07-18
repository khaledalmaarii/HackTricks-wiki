# Wifi Pcap Analysis

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

## BSSIDを確認する

WireSharkを使用してWifiの主要なトラフィックをキャプチャした場合、_Wireless --> WLAN Traffic_を使用してキャプチャのすべてのSSIDを調査し始めることができます：

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### ブルートフォース

その画面の1つの列は、**pcap内に認証が見つかったかどうか**を示しています。もしそうであれば、`aircrack-ng`を使用してブルートフォースを試みることができます：
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
例えば、PSK（事前共有キー）を保護するWPAパスフレーズを取得し、後でトラフィックを復号化するために必要です。

## ビーコン / サイドチャネルのデータ

**Wifiネットワークのビーコン内でデータが漏洩していると疑う場合**、次のようなフィルターを使用してネットワークのビーコンを確認できます：`wlan contains <NAMEofNETWORK>`、または`wlan.ssid == "NAMEofNETWORK"`フィルタリングされたパケット内で疑わしい文字列を検索します。

## Wifiネットワーク内の不明なMACアドレスを見つける

次のリンクは、**Wifiネットワーク内でデータを送信しているマシンを見つける**のに役立ちます：

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

すでに**MACアドレスを知っている場合は、出力からそれらを削除**するために、次のようなチェックを追加できます：`&& !(wlan.addr==5c:51:88:31:a0:3b)`

ネットワーク内で通信している**不明なMAC**アドレスを検出したら、次のような**フィルター**を使用できます：`wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`トラフィックをフィルタリングします。ftp/http/ssh/telnetフィルターは、トラフィックを復号化した場合に便利です。

## トラフィックを復号化する

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../.gitbook/assets/image (499).png>)

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
