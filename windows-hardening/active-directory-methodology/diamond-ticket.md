# Diamanttiket

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

## Diamanttiket

**Wie ein goldenes Ticket** ist ein Diamanttiket ein TGT, das verwendet werden kann, um **auf jeden Dienst als beliebiger Benutzer zuzugreifen**. Ein goldenes Ticket wird vollständig offline gefälscht, mit dem krbtgt-Hash dieser Domäne verschlüsselt und dann in eine Anmeldesitzung übergeben. Da Domänencontroller TGTs, die sie (oder es) legitim ausgestellt haben, nicht verfolgen, akzeptieren sie bereitwillig TGTs, die mit ihrem eigenen krbtgt-Hash verschlüsselt sind.

Es gibt zwei gängige Techniken, um die Verwendung von goldenen Tickets zu erkennen:

* Suchen Sie nach TGS-REQs, die keine entsprechenden AS-REQs haben.
* Suchen Sie nach TGTs mit unsinnigen Werten, wie z.B. der standardmäßigen 10-jährigen Lebensdauer von Mimikatz.

Ein **Diamanttiket** wird erstellt, indem die Felder eines legitimen TGTs, das von einem DC ausgestellt wurde, **modifiziert** werden. Dies wird erreicht, indem ein TGT angefordert, mit dem krbtgt-Hash der Domäne entschlüsselt, die gewünschten Felder des Tickets modifiziert und anschließend erneut verschlüsselt werden. Dadurch werden die beiden oben genannten Mängel eines goldenen Tickets überwunden, da:

* TGS-REQs eine vorhergehende AS-REQ haben werden.
* Das TGT wurde von einem DC ausgestellt, was bedeutet, dass es alle korrekten Details aus der Kerberos-Richtlinie der Domäne enthält. Obwohl diese in einem goldenen Ticket genau gefälscht werden können, ist es komplexer und fehleranfälliger.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
