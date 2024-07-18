{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}


# BSSIDの確認

WireSharkを使用してWifiの主要トラフィックを含むキャプチャを受信した場合、_Wireless --> WLAN Traffic_でキャプチャのすべてのSSIDを調査を開始できます:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## ブルートフォース

その画面の列の1つは、**pcap内で認証情報が見つかったかどうか**を示します。その場合、`aircrack-ng`を使用してブルートフォース攻撃を試みることができます:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
# ビーコン/サイドチャネル内のデータ

**Wifiネットワークのビーコン内でデータが漏洩している**と疑う場合は、次のようなフィルタを使用してネットワークのビーコンをチェックできます：`wlan contains <NAMEofNETWORK>`、または`wlan.ssid == "NAMEofNETWORK"`。フィルタされたパケット内で疑わしい文字列を検索します。

# Wifiネットワーク内の不明なMACアドレスを見つける

次のリンクは、**Wifiネットワーク内でデータを送信している機器を見つける**のに役立ちます：

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

すでに知っている**MACアドレスを出力から削除**する場合は、次のようなチェックを追加します：`&& !(wlan.addr==5c:51:88:31:a0:3b)`

ネットワーク内で通信している**不明なMAC**アドレスを検出したら、次のような**フィルタ**を使用できます：`wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`。ftp/http/ssh/telnetフィルタは、トラフィックを復号化している場合に有用です。

# トラフィックの復号化

編集 --> 設定 --> プロトコル --> IEEE 802.11 --> 編集

![](<../../../.gitbook/assets/image (426).png>)
