# Skeleton Key

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Skeleton Key-Angriff

Der **Skeleton Key-Angriff** ist eine ausgeklügelte Technik, die es Angreifern ermöglicht, die **Active Directory-Authentifizierung zu umgehen**, indem sie ein Master-Passwort in den Domänencontroller einschleusen. Dadurch kann der Angreifer sich als beliebiger Benutzer authentifizieren, ohne deren Passwort zu kennen, und erhält effektiv **uneingeschränkten Zugriff** auf die Domäne.

Dies kann mit [Mimikatz](https://github.com/gentilkiwi/mimikatz) durchgeführt werden. Um diesen Angriff durchzuführen, sind **Domänenadministratorrechte erforderlich**, und der Angreifer muss jeden Domänencontroller ins Visier nehmen, um einen umfassenden Einbruch zu gewährleisten. Die Wirkung des Angriffs ist jedoch vorübergehend, da das **Neustarten des Domänencontrollers die Malware beseitigt**, was eine erneute Implementierung für dauerhaften Zugriff erforderlich macht.

Die **Ausführung des Angriffs** erfordert einen einzigen Befehl: `misc::skeleton`.

## Abwehrmaßnahmen

Zu den Abwehrstrategien gegen solche Angriffe gehört die Überwachung bestimmter Ereignis-IDs, die auf die Installation von Diensten oder die Verwendung sensibler Berechtigungen hinweisen. Insbesondere das Suchen nach System-Ereignis-ID 7045 oder Sicherheits-Ereignis-ID 4673 kann verdächtige Aktivitäten aufdecken. Darüber hinaus kann das Ausführen von `lsass.exe` als geschützter Prozess die Bemühungen der Angreifer erheblich behindern, da sie einen Kernelmodustreiber verwenden müssen, was die Komplexität des Angriffs erhöht.

Hier sind die PowerShell-Befehle zur Verbesserung der Sicherheitsmaßnahmen:

- Um die Installation verdächtiger Dienste zu erkennen, verwenden Sie: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Speziell zur Erkennung des Treibers von Mimikatz kann der folgende Befehl verwendet werden: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Zur Stärkung von `lsass.exe` wird empfohlen, es als geschützten Prozess zu aktivieren: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Die Überprüfung nach einem Systemneustart ist entscheidend, um sicherzustellen, dass die Schutzmaßnahmen erfolgreich angewendet wurden. Dies kann mit folgendem Befehl erreicht werden: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Referenzen
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
