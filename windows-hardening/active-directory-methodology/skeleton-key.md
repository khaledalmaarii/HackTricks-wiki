# Skeleton Key

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

## Skeleton Key Attack

Der **Skeleton Key Angriff** ist eine ausgeklügelte Technik, die es Angreifern ermöglicht, die **Active Directory-Authentifizierung zu umgehen**, indem sie ein **Master-Passwort** in den Domänencontroller injizieren. Dies ermöglicht es dem Angreifer, sich **als jeder Benutzer** zu authentifizieren, ohne dessen Passwort, was ihm effektiv **uneingeschränkten Zugriff** auf die Domäne gewährt.

Er kann mit [Mimikatz](https://github.com/gentilkiwi/mimikatz) durchgeführt werden. Um diesen Angriff durchzuführen, sind **Domain Admin-Rechte Voraussetzung**, und der Angreifer muss jeden Domänencontroller anvisieren, um einen umfassenden Zugriff zu gewährleisten. Der Effekt des Angriffs ist jedoch vorübergehend, da **ein Neustart des Domänencontrollers die Malware beseitigt**, was eine erneute Implementierung für anhaltenden Zugriff erforderlich macht.

**Die Ausführung des Angriffs** erfordert einen einzigen Befehl: `misc::skeleton`.

## Mitigations

Minderungsstrategien gegen solche Angriffe umfassen die Überwachung spezifischer Ereignis-IDs, die die Installation von Diensten oder die Nutzung sensibler Berechtigungen anzeigen. Insbesondere die Suche nach Systemereignis-ID 7045 oder Sicherheitsereignis-ID 4673 kann verdächtige Aktivitäten aufdecken. Darüber hinaus kann das Ausführen von `lsass.exe` als geschützter Prozess die Bemühungen der Angreifer erheblich behindern, da dies erfordert, dass sie einen Kernelmodus-Treiber verwenden, was die Komplexität des Angriffs erhöht.

Hier sind die PowerShell-Befehle zur Verbesserung der Sicherheitsmaßnahmen:

- Um die Installation verdächtiger Dienste zu erkennen, verwenden Sie: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Um speziell den Treiber von Mimikatz zu erkennen, kann der folgende Befehl verwendet werden: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Um `lsass.exe` zu stärken, wird empfohlen, es als geschützten Prozess zu aktivieren: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Die Überprüfung nach einem Systemneustart ist entscheidend, um sicherzustellen, dass die Schutzmaßnahmen erfolgreich angewendet wurden. Dies ist erreichbar durch: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## References
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
