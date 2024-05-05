# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos **Workflows zu erstellen** und zu **automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## **Zugriffssteuerungsliste (ACL)**

Eine Zugriffssteuerungsliste (ACL) besteht aus einer geordneten Reihe von Zugriffssteuerungseinträgen (ACEs), die den Schutz für ein Objekt und dessen Eigenschaften festlegen. Im Wesentlichen definiert eine ACL, welche Aktionen von welchen Sicherheitsprinzipalen (Benutzern oder Gruppen) auf einem bestimmten Objekt erlaubt oder verweigert werden.

Es gibt zwei Arten von ACLs:

* **Discretionary Access Control List (DACL):** Legt fest, welche Benutzer und Gruppen Zugriff auf ein Objekt haben oder nicht.
* **System Access Control List (SACL):** Steuert die Überwachung von Zugriffsversuchen auf ein Objekt.

Der Prozess des Zugriffs auf eine Datei beinhaltet, dass das System den Sicherheitsdeskriptor des Objekts mit dem Zugriffstoken des Benutzers vergleicht, um zu bestimmen, ob der Zugriff gewährt werden sollte und in welchem Umfang, basierend auf den ACEs.

### **Wichtige Komponenten**

* **DACL:** Enthält ACEs, die Zugriffsberechtigungen für Benutzer und Gruppen für ein Objekt gewähren oder verweigern. Es ist im Wesentlichen die Haupt-ACL, die Zugriffsrechte festlegt.
* **SACL:** Wird zur Überwachung des Zugriffs auf Objekte verwendet, wobei ACEs die Arten von Zugriffen definieren, die im Sicherheitsereignisprotokoll protokolliert werden sollen. Dies kann von unschätzbarem Wert sein, um nicht autorisierte Zugriffsversuche zu erkennen oder Zugriffsprobleme zu beheben.

### **Systeminteraktion mit ACLs**

Jede Benutzersitzung ist mit einem Zugriffstoken verbunden, das Sicherheitsinformationen enthält, die für diese Sitzung relevant sind, einschließlich Benutzer-, Gruppenidentitäten und Berechtigungen. Dieses Token enthält auch eine Anmelde-SID, die die Sitzung eindeutig identifiziert.

Die lokale Sicherheitsbehörde (LSASS) bearbeitet Zugriffsanfragen auf Objekte, indem sie die DACL nach ACEs überprüft, die dem Sicherheitsprinzipal, der auf den Zugriff zugreift, entsprechen. Wenn keine relevanten ACEs gefunden werden, wird der Zugriff sofort gewährt. Andernfalls vergleicht LSASS die ACEs mit der SID des Sicherheitsprinzipals im Zugriffstoken, um die Zugangsberechtigung zu bestimmen.

### **Zusammengefasster Prozess**

* **ACLs:** Definieren Zugriffsberechtigungen über DACLs und Überwachungsregeln über SACLs.
* **Zugriffstoken:** Enthält Benutzer-, Gruppen- und Berechtigungsinformationen für eine Sitzung.
* **Zugriffsentscheidung:** Wird durch den Vergleich von DACL-ACEs mit dem Zugriffstoken getroffen; SACLs werden für die Überwachung verwendet.

### ACEs

Es gibt **drei Haupttypen von Zugriffssteuerungseinträgen (ACEs)**:

* **Zugriff verweigert ACE**: Dieser ACE verweigert explizit den Zugriff auf ein Objekt für bestimmte Benutzer oder Gruppen (in einer DACL).
* **Zugriff erlaubt ACE**: Dieser ACE gewährt explizit den Zugriff auf ein Objekt für bestimmte Benutzer oder Gruppen (in einer DACL).
* **Systemüberwachungs-ACE**: Positioniert innerhalb einer Systemzugriffssteuerungsliste (SACL) ist dieser ACE dafür verantwortlich, Überwachungsprotokolle bei Zugriffsversuchen auf ein Objekt durch Benutzer oder Gruppen zu generieren. Es dokumentiert, ob der Zugriff erlaubt oder verweigert wurde und die Art des Zugriffs.

Jeder ACE hat **vier wesentliche Komponenten**:

1. Die **Sicherheitskennung (SID)** des Benutzers oder der Gruppe (oder deren Hauptname in einer grafischen Darstellung).
2. Eine **Flagge**, die den ACE-Typ identifiziert (Zugriff verweigert, erlaubt oder Systemüberwachung).
3. **Vererbungsflaggen**, die bestimmen, ob untergeordnete Objekte den ACE von ihrem übergeordneten Objekt erben können.
4. Ein [**Zugriffsmaskenwert**](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), ein 32-Bit-Wert, der die gewährten Rechte des Objekts angibt.

Die Zugriffsbestimmung erfolgt durch sequentielles Prüfen jedes ACE, bis:

* Ein **Zugriff verweigert ACE** die angeforderten Rechte explizit einem im Zugriffstoken identifizierten Treuhänder verweigert.
* **Zugriff-erlaubte ACE(s)** gewähren einem Treuhänder im Zugriffstoken explizit alle angeforderten Rechte.
* Nach Überprüfung aller ACEs, wenn ein angeforderter Recht **nicht explizit erlaubt wurde**, wird der Zugriff implizit **verweigert**.

### Reihenfolge der ACEs

Die Art und Weise, wie **ACEs** (Regeln, die angeben, wer auf etwas zugreifen kann oder nicht) in einer Liste namens **DACL** platziert werden, ist sehr wichtig. Dies liegt daran, dass das System, sobald es den Zugriff basierend auf diesen Regeln gewährt oder verweigert, nicht mehr auf den Rest schaut.

Es gibt eine beste Methode, um diese ACEs zu organisieren, und sie wird als **"kanonische Reihenfolge"** bezeichnet. Diese Methode hilft sicherzustellen, dass alles reibungslos und fair funktioniert. So funktioniert es für Systeme wie **Windows 2000** und **Windows Server 2003**:

* Zuerst werden alle Regeln, die **speziell für dieses Element erstellt wurden**, vor denen platziert, die von anderswo stammen, wie einem übergeordneten Ordner.
* In diesen spezifischen Regeln werden diejenigen, die **"nein" (verweigern)** sagen, vor denen platziert, die **"ja" (erlauben)** sagen.
* Für die Regeln, die von anderswo stammen, beginnen Sie mit denen aus der **nächsten Quelle**, wie dem übergeordneten Ordner, und gehen dann von dort aus zurück. Wiederum setzen Sie **"nein"** vor **"ja".**

Diese Einrichtung hilft auf zwei große Arten:

* Sie stellt sicher, dass ein spezifisches **"nein"** respektiert wird, unabhängig davon, welche anderen **"ja"**-Regeln vorhanden sind.
* Sie lässt den Besitzer eines Elements das **letzte Wort** darüber haben, wer Zugang erhält, bevor Regeln von übergeordneten Ordnern oder weiter hinten ins Spiel kommen.

Indem man dies auf diese Weise macht, kann der Besitzer einer Datei oder eines Ordners sehr genau festlegen, wer Zugriff erhält, um sicherzustellen, dass die richtigen Personen Zugang haben und die falschen nicht.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Also geht es bei dieser **"kanonischen Reihenfolge"** darum, sicherzustellen, dass die Zugriffsregeln klar sind und gut funktionieren, spezifische Regeln zuerst zu platzieren und alles auf intelligente Weise zu organisieren.

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos **Workflows zu erstellen** und zu **automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
### GUI Beispiel

[**Beispiel von hier**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Dies ist das klassische Sicherheitstab eines Ordners, das die ACL, DACL und ACEs zeigt:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Wenn wir auf die **Erweitert-Schaltfläche** klicken, erhalten wir weitere Optionen wie Vererbung:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Und wenn Sie einen Sicherheitsprinzipal hinzufügen oder bearbeiten:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Und zuletzt haben wir die SACL im Überwachungs-Tab:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Erklärung der Zugriffskontrolle auf vereinfachte Weise

Beim Verwalten des Zugriffs auf Ressourcen, wie z. B. einen Ordner, verwenden wir Listen und Regeln, die als Zugriffssteuerungslisten (ACLs) und Zugriffssteuerungseinträge (ACEs) bekannt sind. Diese definieren, wer auf bestimmte Daten zugreifen kann oder nicht.

#### Zugriff für eine bestimmte Gruppe verweigern

Stellen Sie sich vor, Sie haben einen Ordner namens Kosten und möchten, dass jeder darauf zugreifen kann, außer einem Marketingteam. Durch korrektes Einrichten der Regeln können wir sicherstellen, dass dem Marketingteam der Zugriff explizit verweigert wird, bevor allen anderen der Zugriff gestattet wird. Dies wird erreicht, indem die Regel zum Verweigern des Zugriffs für das Marketingteam vor der Regel platziert wird, die allen anderen den Zugriff gestattet.

#### Zugriff für ein bestimmtes Mitglied einer verweigerten Gruppe ermöglichen

Angenommen, Bob, der Marketingdirektor, benötigt Zugriff auf den Kostenordner, obwohl das Marketingteam im Allgemeinen keinen Zugriff haben sollte. Wir können eine spezifische Regel (ACE) für Bob hinzufügen, die ihm Zugriff gewährt, und sie vor der Regel platzieren, die den Zugriff für das Marketingteam verweigert. Auf diese Weise erhält Bob Zugriff, obwohl die allgemeine Einschränkung für sein Team gilt.

#### Verständnis der Zugriffssteuerungseinträge

ACEs sind die einzelnen Regeln in einer ACL. Sie identifizieren Benutzer oder Gruppen, geben an, welcher Zugriff erlaubt oder verweigert ist, und bestimmen, wie diese Regeln auf Unterobjekte angewendet werden (Vererbung). Es gibt zwei Hauptarten von ACEs:

* **Generische ACEs**: Diese gelten allgemein und beeinflussen entweder alle Arten von Objekten oder unterscheiden nur zwischen Containern (wie Ordnern) und Nicht-Containern (wie Dateien). Zum Beispiel eine Regel, die Benutzern erlaubt, den Inhalt eines Ordners zu sehen, aber nicht auf die Dateien darin zuzugreifen.
* **Objektspezifische ACEs**: Diese bieten eine präzisere Steuerung, indem Regeln für bestimmte Objekttypen oder sogar einzelne Eigenschaften innerhalb eines Objekts festgelegt werden können. Zum Beispiel könnte in einem Verzeichnis von Benutzern eine Regel einem Benutzer erlauben, seine Telefonnummer zu aktualisieren, aber nicht seine Anmeldezeiten.

Jeder ACE enthält wichtige Informationen wie auf wen die Regel angewendet wird (unter Verwendung einer Sicherheitskennung oder SID), was die Regel erlaubt oder verweigert (unter Verwendung einer Zugriffsmaske) und wie sie von anderen Objekten geerbt wird.

#### Hauptunterschiede zwischen den ACE-Typen

* **Generische ACEs** sind für einfache Zugriffskontrollszenarien geeignet, bei denen dieselbe Regel auf alle Aspekte eines Objekts oder auf alle Objekte innerhalb eines Containers angewendet wird.
* **Objektspezifische ACEs** werden für komplexere Szenarien verwendet, insbesondere in Umgebungen wie Active Directory, in denen möglicherweise der Zugriff auf bestimmte Eigenschaften eines Objekts unterschiedlich gesteuert werden muss.

Zusammenfassend helfen ACLs und ACEs dabei, präzise Zugriffskontrollen zu definieren, um sicherzustellen, dass nur die richtigen Personen oder Gruppen Zugriff auf sensible Informationen oder Ressourcen haben, wobei die Zugriffsrechte bis auf die Ebene einzelner Eigenschaften oder Objekttypen angepasst werden können.

### Layout des Zugriffskontrolleintrags

| ACE-Feld   | Beschreibung                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Typ        | Flagge, die den Typ des ACE angibt. Windows 2000 und Windows Server 2003 unterstützen sechs Arten von ACE: Drei generische ACE-Typen, die an alle schützbaren Objekte angehängt sind. Drei objektspezifische ACE-Typen, die für Active Directory-Objekte auftreten können.                                                                                                                                                                                                                                                            |
| Flags       | Satz von Bitflags, die Vererbung und Überwachung steuern.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Größe        | Anzahl der Bytes im Speicher, die für den ACE allokiert sind.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Zugriffsmaske | 32-Bit-Wert, dessen Bits den Zugriffsrechten für das Objekt entsprechen. Bits können entweder ein- oder ausgeschaltet sein, aber die Bedeutung der Einstellung hängt vom ACE-Typ ab. Wenn beispielsweise das Bit, das dem Recht zum Lesen von Berechtigungen entspricht, eingeschaltet ist und der ACE-Typ Verweigern ist, verweigert der ACE das Recht, die Berechtigungen des Objekts zu lesen. Wenn dasselbe Bit eingeschaltet ist, der ACE-Typ jedoch Zulassen ist, gewährt der ACE das Recht, die Berechtigungen des Objekts zu lesen. Weitere Details zur Zugriffsmaske finden Sie in der nächsten Tabelle. |
| SID         | Identifiziert einen Benutzer oder eine Gruppe, dessen Zugriff durch diesen ACE gesteuert oder überwacht wird.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Layout der Zugriffsmaske

| Bit (Bereich) | Bedeutung                            | Beschreibung/Beispiel                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Objektspezifische Zugriffsrechte      | Daten lesen, Ausführen, Daten anhängen           |
| 16 - 22     | Standardzugriffsrechte             | Löschen, ACL schreiben, Besitzer schreiben            |
| 23          | Kann auf Sicherheits-ACL zugreifen            |                                           |
| 24 - 27     | Reserviert                           |                                           |
| 28          | Generisch ALLE (Lesen, Schreiben, Ausführen) | Alles darunter                          |
| 29          | Generisches Ausführen                    | Alles, was zum Ausführen eines Programms erforderlich ist |
| 30          | Generisches Schreiben                      | Alles, was zum Schreiben in eine Datei erforderlich ist   |
| 31          | Generisches Lesen                       | Alles, was zum Lesen einer Datei erforderlich ist       |

## Referenzen

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/\_ntfsacl\_ht.htm](https://www.coopware.in2.info/\_ntfsacl\_ht.htm)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** möchten oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos Workflows zu erstellen und zu **automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute zugreifen:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
