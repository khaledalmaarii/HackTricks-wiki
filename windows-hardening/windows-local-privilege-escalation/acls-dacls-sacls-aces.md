# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## **Zugriffssteuerungsliste (ACL)**

Eine Zugriffssteuerungsliste (ACL) besteht aus einer geordneten Menge von Zugriffskontrolleinträgen (ACEs), die den Schutz für ein Objekt und seine Eigenschaften festlegen. Im Wesentlichen legt eine ACL fest, welche Aktionen von welchen Sicherheitsprinzipalen (Benutzern oder Gruppen) auf einem bestimmten Objekt erlaubt oder verweigert werden.

Es gibt zwei Arten von ACLs:

- **Discretionary Access Control List (DACL):** Gibt an, welche Benutzer und Gruppen Zugriff auf ein Objekt haben oder nicht haben.
- **System Access Control List (SACL):** Steuert die Überwachung von Zugriffsversuchen auf ein Objekt.

Der Prozess des Zugriffs auf eine Datei beinhaltet, dass das System den Sicherheitsdeskriptor des Objekts mit dem Zugriffstoken des Benutzers vergleicht, um zu bestimmen, ob der Zugriff gewährt werden soll und in welchem Umfang, basierend auf den ACEs.

### **Wichtige Komponenten**

- **DACL:** Enthält ACEs, die Zugriffsberechtigungen für Benutzer und Gruppen für ein Objekt gewähren oder verweigern. Es ist im Wesentlichen die Haupt-ACL, die Zugriffsrechte festlegt.

- **SACL:** Wird zur Überwachung des Zugriffs auf Objekte verwendet, wobei ACEs die Arten von Zugriffen definieren, die im Sicherheitsereignisprotokoll protokolliert werden sollen. Dies kann von unschätzbarem Wert sein, um unbefugte Zugriffsversuche zu erkennen oder Zugriffsprobleme zu beheben.

### **Systeminteraktion mit ACLs**

Jede Benutzersitzung ist mit einem Zugriffstoken verbunden, das sicherheitsrelevante Informationen für diese Sitzung enthält, einschließlich Benutzer-, Gruppenidentitäten und Privilegien. Dieses Token enthält auch eine Anmelde-SID, die die Sitzung eindeutig identifiziert.

Der Local Security Authority (LSASS) verarbeitet Zugriffsanfragen auf Objekte, indem er die DACL nach ACEs durchsucht, die mit dem Sicherheitsprinzip übereinstimmen, das den Zugriff versucht. Wenn keine relevanten ACEs gefunden werden, wird der Zugriff sofort gewährt. Andernfalls vergleicht LSASS die ACEs mit der SID des Sicherheitsprinzips im Zugriffstoken, um die Zugriffsberechtigung zu bestimmen.

### **Zusammengefasster Prozess**

- **ACLs:** Definieren Zugriffsberechtigungen über DACLs und Überwachungsregeln über SACLs.
- **Zugriffstoken:** Enthält Benutzer-, Gruppen- und Privilegieninformationen für eine Sitzung.
- **Zugriffsentscheidung:** Wird durch den Vergleich von DACL ACEs mit dem Zugriffstoken getroffen; SACLs werden zur Überwachung verwendet.


### ACEs

Es gibt **drei Haupttypen von Zugriffskontrolleinträgen (ACEs)**:

- **Access Denied ACE**: Dieser ACE verweigert explizit den Zugriff auf ein Objekt für bestimmte Benutzer oder Gruppen (in einer DACL).
- **Access Allowed ACE**: Dieser ACE gewährt explizit den Zugriff auf ein Objekt für bestimmte Benutzer oder Gruppen (in einer DACL).
- **System Audit ACE**: Dieser ACE befindet sich in einer System Access Control List (SACL) und ist dafür verantwortlich, Auditprotokolle bei Zugriffsversuchen auf ein Objekt durch Benutzer oder Gruppen zu generieren. Es dokumentiert, ob der Zugriff erlaubt oder verweigert wurde und die Art des Zugriffs.

Jeder ACE hat **vier wesentliche Komponenten**:

1. Die **Sicherheitskennung (SID)** des Benutzers oder der Gruppe (oder deren Prinzipalname in einer grafischen Darstellung).
2. Eine **Flagge**, die den ACE-Typ identifiziert (Zugriff verweigert, erlaubt oder Systemüberwachung).
3. **Vererbungsflaggen**, die bestimmen, ob untergeordnete Objekte den ACE von ihrem übergeordneten Objekt erben können.
4. Eine **[Zugriffsmaske](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)**, ein 32-Bit-Wert, der die gewährten Rechte des Objekts angibt.

Die Zugriffsentscheidung erfolgt durch sequenzielle Prüfung jedes ACE, bis:

- Ein **Access-Denied ACE** die angeforderten Rechte explizit für einen im Zugriffstoken identifizierten Trustee verweigert.
- **Access-Allowed ACE(s)** gewähren explizit alle angeforderten Rechte für einen Trustee im Zugriffstoken.
- Nach Überprüfung aller ACEs, wenn ein angeforderter Recht **nicht explizit erlaubt** wurde, wird der Zugriff implizit **verweigert**.


### Reihenfolge der ACEs

Die Art und Weise, wie **ACEs** (Regeln, die angeben, wer auf etwas zugreifen kann oder nicht) in einer Liste namens **DACL** platziert werden, ist sehr wichtig. Dies liegt daran, dass das System nach der Gewährung oder Verweigerung des Zugriffs basierend auf diesen Regeln nicht weiter sucht.

Es gibt eine beste Methode, um diese ACEs zu organisieren, und sie wird als **"kanonische Reihenfolge"** bezeichnet. Diese Methode hilft sicherzustellen, dass alles reibungslos und fair funktioniert. So geht es bei Systemen wie **Windows 2000** und **Windows Server 2003**:

- Setzen Sie zuerst alle Regeln, die **speziell für dieses Element** erstellt wurden, vor denen, die von anderswo stammen, wie z.B. einem übergeordneten Ordner.
- Bei diesen spezifischen Regeln setzen Sie diejenigen, die **"nein" (verweigern)** sagen, vor denen, die **"ja" (erlauben)** sagen.
- Bei den Regeln, die von anderswo stammen, beginnen Sie mit denen aus der **nächsten Quelle**, wie dem übergeordneten Ordner, und gehen dann von dort aus zurück. Setzen Sie auch hier **"nein"** vor **"ja".**

Diese Einrichtung hilft auf zwei große Arten:

* Sie stellt sicher, dass eine spezifische **"nein"**-Regel respektiert wird, unabhängig davon, welche anderen **"ja"**-Regeln vorhanden
### GUI-Beispiel

**[Beispiel von hier](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)**

Dies ist das klassische Sicherheitsregisterkarte eines Ordners, das die ACL, DACL und ACEs zeigt:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Wenn wir auf die **Erweitert-Schaltfläche** klicken, erhalten wir weitere Optionen wie Vererbung:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Und wenn Sie einen Sicherheitsprinzipal hinzufügen oder bearbeiten:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Und zuletzt haben wir die SACL im Überwachungsregister:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Erklärung der Zugriffssteuerung in vereinfachter Form

Bei der Verwaltung des Zugriffs auf Ressourcen wie einen Ordner verwenden wir Listen und Regeln, die als Access Control Lists (ACLs) und Access Control Entries (ACEs) bekannt sind. Diese legen fest, wer auf bestimmte Daten zugreifen kann oder nicht.

#### Verweigern des Zugriffs für eine bestimmte Gruppe

Stellen Sie sich vor, Sie haben einen Ordner namens "Kosten" und möchten, dass jeder darauf zugreifen kann, außer einem Marketingteam. Durch korrekte Einrichtung der Regeln können wir sicherstellen, dass dem Marketingteam explizit der Zugriff verweigert wird, bevor allen anderen der Zugriff gestattet wird. Dies wird erreicht, indem die Regel zum Verweigern des Zugriffs für das Marketingteam vor der Regel platziert wird, die allen anderen den Zugriff gestattet.

#### Zugriff für ein bestimmtes Mitglied einer verweigerten Gruppe ermöglichen

Angenommen, Bob, der Marketingdirektor, benötigt Zugriff auf den Ordner "Kosten", obwohl das Marketingteam im Allgemeinen keinen Zugriff haben sollte. Wir können eine spezifische Regel (ACE) für Bob hinzufügen, die ihm Zugriff gewährt, und sie vor der Regel platzieren, die den Zugriff für das Marketingteam verweigert. Auf diese Weise erhält Bob Zugriff, obwohl für sein Team eine allgemeine Einschränkung besteht.

#### Verständnis der Access Control Entries

ACEs sind die einzelnen Regeln in einer ACL. Sie identifizieren Benutzer oder Gruppen, geben an, welcher Zugriff erlaubt oder verweigert wird, und bestimmen, wie diese Regeln auf Unterobjekte angewendet werden (Vererbung). Es gibt zwei Haupttypen von ACEs:

- **Generische ACEs**: Diese gelten allgemein und betreffen entweder alle Arten von Objekten oder unterscheiden nur zwischen Containern (wie Ordnern) und Nicht-Containern (wie Dateien). Zum Beispiel eine Regel, die Benutzern ermöglicht, den Inhalt eines Ordners zu sehen, aber nicht auf die darin enthaltenen Dateien zuzugreifen.

- **Objektspezifische ACEs**: Diese bieten eine präzisere Kontrolle und ermöglichen das Festlegen von Regeln für bestimmte Objekttypen oder sogar einzelne Eigenschaften innerhalb eines Objekts. Zum Beispiel könnte in einem Verzeichnis von Benutzern eine Regel einem Benutzer das Aktualisieren seiner Telefonnummer, aber nicht seiner Anmeldezeiten, ermöglichen.

Jeder ACE enthält wichtige Informationen wie für wen die Regel gilt (unter Verwendung einer Sicherheitskennung oder SID), was die Regel erlaubt oder verweigert (unter Verwendung einer Zugriffsmaske) und wie sie von anderen Objekten geerbt wird.

#### Hauptunterschiede zwischen den ACE-Typen

- **Generische ACEs** eignen sich für einfache Zugriffskontrollszenarien, bei denen dieselbe Regel für alle Aspekte eines Objekts oder für alle Objekte innerhalb eines Containers gilt.

- **Objektspezifische ACEs** werden für komplexere Szenarien verwendet, insbesondere in Umgebungen wie Active Directory, in denen möglicherweise der Zugriff auf bestimmte Eigenschaften eines Objekts unterschiedlich gesteuert werden muss.

Zusammenfassend helfen ACLs und ACEs dabei, präzise Zugriffskontrollen festzulegen und sicherzustellen, dass nur die richtigen Personen oder Gruppen Zugriff auf sensible Informationen oder Ressourcen haben und die Zugriffsrechte bis auf die Ebene einzelner Eigenschaften oder Objekttypen anpassen können.

### Layout der Access Control Entry

| ACE-Feld   | Beschreibung                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Typ        | Flagge, die den Typ des ACE angibt. Windows 2000 und Windows Server 2003 unterstützen sechs Arten von ACE: Drei generische ACE-Typen, die an alle sicherbaren Objekte angehängt sind. Drei objektspezifische ACE-Typen, die für Active Directory-Objekte auftreten können.                                                                                                                                                                                                                                                            |
| Flags       | Satz von Bitflags, die Vererbung und Überwachung steuern.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Größe        | Anzahl der für den ACE zugewiesenen Speicherbytes.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Zugriffsmaske | 32-Bit-Wert, dessen Bits den Zugriffsrechten für das Objekt entsprechen. Bits können entweder aktiviert oder deaktiviert sein, aber die Bedeutung der Einstellung hängt vom ACE-Typ ab. Wenn zum Beispiel das Bit, das dem Recht zum Lesen von Berechtigungen entspricht, aktiviert ist und der ACE-Typ "Verweigern" ist, verweigert der ACE das Recht, die Berechtigungen des Objekts zu lesen. Wenn dasselbe Bit aktiviert ist, aber der ACE-Typ "Zulassen" ist, gewährt der ACE das Recht, die Berechtigungen des Objekts zu lesen. Weitere Details zur Zugriffsmaske finden Sie in der nächsten Tabelle. |
| SID         | Identifiziert einen Benutzer oder eine Gruppe, dessen Zugriff durch diesen ACE gesteuert oder überwacht wird.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Layout der Zugriffsmaske

| Bit (Bereich) | Bedeutung                            | Beschreibung/Beispiel                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Objektspezifische Zugriffsrechte      | Daten lesen, Ausführen, Daten anhängen           |
| 16 - 22     | Standardzugriffsrechte             | Löschen, ACL schreiben, Besitzer schreiben            |
| 23          | Kann auf Sicherheits-ACL zugreifen            |                                           |
| 24 - 27     | Reserviert                           |                                           |
| 28          | Generisch ALL (Lesen, Schreiben, Ausführen) | Alles darunter                          |
| 29          | Generisch Ausführen                    | Alles, was zum Ausführen eines Programms erforderlich ist |
| 30          | Generisch Schreiben                      | Alles, was zum Schreiben in eine Datei erforderlich ist   |
| 31          | Generisch Lesen                       | Alles, was zum Lesen einer Datei erforderlich ist       |

## Referenzen

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https
