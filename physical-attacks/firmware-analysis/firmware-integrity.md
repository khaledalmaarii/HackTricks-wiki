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

## ファームウェアの整合性

**カスタムファームウェアおよび/またはコンパイルされたバイナリは、整合性または署名検証の欠陥を悪用するためにアップロードできます**。バックドアバインドシェルのコンパイルには、以下の手順を実行できます：

1. ファームウェアは、firmware-mod-kit (FMK) を使用して抽出できます。
2. 対象のファームウェアアーキテクチャとエンディアンネスを特定する必要があります。
3. Buildroot または環境に適した他の方法を使用してクロスコンパイラを構築できます。
4. クロスコンパイラを使用してバックドアを構築できます。
5. バックドアを抽出したファームウェアの /usr/bin ディレクトリにコピーできます。
6. 適切な QEMU バイナリを抽出したファームウェアの rootfs にコピーできます。
7. chroot と QEMU を使用してバックドアをエミュレートできます。
8. netcat を介してバックドアにアクセスできます。
9. QEMU バイナリは、抽出したファームウェアの rootfs から削除する必要があります。
10. 修正されたファームウェアは、FMK を使用して再パッケージ化できます。
11. バックドア付きファームウェアは、ファームウェア分析ツールキット (FAT) を使用してエミュレートし、netcat を使用してターゲットバックドアの IP とポートに接続することでテストできます。

動的分析、ブートローダー操作、またはハードウェアセキュリティテストを通じてルートシェルがすでに取得されている場合、インプラントやリバースシェルなどの事前コンパイルされた悪意のあるバイナリを実行できます。Metasploit フレームワークや 'msfvenom' のような自動ペイロード/インプラントツールを以下の手順で活用できます：

1. 対象のファームウェアアーキテクチャとエンディアンネスを特定する必要があります。
2. Msfvenom を使用して、ターゲットペイロード、攻撃者ホスト IP、リスニングポート番号、ファイルタイプ、アーキテクチャ、プラットフォーム、および出力ファイルを指定できます。
3. ペイロードを侵害されたデバイスに転送し、実行権限があることを確認します。
4. Metasploit を準備し、msfconsole を起動してペイロードに応じて設定を構成します。
5. 侵害されたデバイスで meterpreter リバースシェルを実行できます。
6. meterpreter セッションが開くときに監視できます。
7. ポストエクスプロイト活動を実行できます。

可能であれば、起動スクリプト内の脆弱性を悪用して、再起動を跨いでデバイスへの永続的なアクセスを取得できます。これらの脆弱性は、起動スクリプトが信頼できないマウントされた場所（SDカードやルートファイルシステムの外にデータを保存するために使用されるフラッシュボリュームなど）にあるコードを参照、[シンボリックリンク](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data) するか、依存する場合に発生します。

## 参考文献
* 詳細情報は [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/) を確認してください。

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
