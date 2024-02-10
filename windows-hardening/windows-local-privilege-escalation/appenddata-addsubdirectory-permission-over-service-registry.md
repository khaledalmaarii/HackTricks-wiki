<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


**Der ursprüngliche Beitrag befindet sich unter** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Zusammenfassung

Es wurden zwei Registry-Schlüssel gefunden, die vom aktuellen Benutzer beschreibbar sind:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Es wurde vorgeschlagen, die Berechtigungen des **RpcEptMapper**-Dienstes mit der **regedit GUI** zu überprüfen, insbesondere das Fenster **Erweiterte Sicherheitseinstellungen** und den Tab **Effektive Berechtigungen**. Dieser Ansatz ermöglicht die Bewertung der gewährten Berechtigungen für bestimmte Benutzer oder Gruppen, ohne dass jede einzelne Zugriffskontrolle (ACE) einzeln untersucht werden muss.

Ein Screenshot zeigte die Berechtigungen, die einem Benutzer mit niedrigen Rechten zugewiesen waren, darunter die Berechtigung **Unterschlüssel erstellen**. Diese Berechtigung, auch als **AppendData/AddSubdirectory** bezeichnet, entspricht den Ergebnissen des Skripts.

Es wurde festgestellt, dass bestimmte Werte nicht direkt geändert werden können, aber die Möglichkeit besteht, neue Unterschlüssel zu erstellen. Als Beispiel wurde der Versuch hervorgehoben, den Wert **ImagePath** zu ändern, was zu einer Zugriffsverweigerung führte.

Trotz dieser Einschränkungen wurde ein Potenzial für Privilegieneskalation identifiziert, indem der **Performance**-Unterschlüssel innerhalb der Registrierungsstruktur des **RpcEptMapper**-Dienstes genutzt wird, ein Unterschlüssel, der standardmäßig nicht vorhanden ist. Dadurch könnte eine DLL-Registrierung und Leistungsüberwachung ermöglicht werden.

Es wurde Dokumentation über den **Performance**-Unterschlüssel und seine Verwendung für die Leistungsüberwachung konsultiert, was zur Entwicklung einer Proof-of-Concept-DLL führte. Diese DLL, die die Implementierung der Funktionen **OpenPerfData**, **CollectPerfData** und **ClosePerfData** demonstriert, wurde über **rundll32** getestet und bestätigte ihren erfolgreichen Betrieb.

Das Ziel bestand darin, den **RPC-Endpunkt-Mapper-Dienst** dazu zu bringen, die erstellte Performance-DLL zu laden. Beobachtungen zeigten, dass die Ausführung von WMI-Klassenabfragen im Zusammenhang mit Leistungsdaten über PowerShell zur Erstellung einer Protokolldatei führte, was die Ausführung beliebigen Codes unter dem Kontext **LOCAL SYSTEM** ermöglichte und somit erhöhte Privilegien gewährte.

Die Persistenz und potenziellen Auswirkungen dieser Schwachstelle wurden hervorgehoben, wobei ihre Relevanz für Post-Exploitation-Strategien, laterale Bewegung und die Umgehung von Antiviren-/EDR-Systemen betont wurde.

Obwohl die Schwachstelle ursprünglich unbeabsichtigt durch das Skript offengelegt wurde, wurde betont, dass ihre Ausnutzung auf veraltete Windows-Versionen (z. B. **Windows 7 / Server 2008 R2**) beschränkt ist und lokalen Zugriff erfordert.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
