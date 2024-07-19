# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

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

## **Zugriffskontrollliste (ACL)**

Eine Zugriffskontrollliste (ACL) besteht aus einer geordneten Menge von Zugriffskontrolleinträgen (ACEs), die die Schutzmaßnahmen für ein Objekt und dessen Eigenschaften festlegen. Im Wesentlichen definiert eine ACL, welche Aktionen von welchen Sicherheitsprinzipalen (Benutzern oder Gruppen) auf einem bestimmten Objekt erlaubt oder verweigert sind.

Es gibt zwei Arten von ACLs:

* **Discretionary Access Control List (DACL):** Gibt an, welche Benutzer und Gruppen Zugriff auf ein Objekt haben oder nicht haben.
* **System Access Control List (SACL):** Regelt die Überwachung von Zugriffsversuchen auf ein Objekt.

Der Prozess des Zugriffs auf eine Datei umfasst die Überprüfung des Sicherheitsdeskriptors des Objekts durch das System gegen das Zugriffstoken des Benutzers, um zu bestimmen, ob der Zugriff gewährt werden soll und in welchem Umfang, basierend auf den ACEs.

### **Wichtige Komponenten**

* **DACL:** Enthält ACEs, die Benutzern und Gruppen Zugriffsberechtigungen für ein Objekt gewähren oder verweigern. Es ist im Wesentlichen die Haupt-ACL, die die Zugriffsrechte diktiert.
* **SACL:** Wird zur Überwachung des Zugriffs auf Objekte verwendet, wobei ACEs die Arten von Zugriff definieren, die im Sicherheitsereignisprotokoll protokolliert werden. Dies kann von unschätzbarem Wert sein, um unbefugte Zugriffsversuche zu erkennen oder Zugriffsprobleme zu beheben.

### **Systeminteraktion mit ACLs**

Jede Benutzersitzung ist mit einem Zugriffstoken verbunden, das sicherheitsrelevante Informationen für diese Sitzung enthält, einschließlich Benutzer-, Gruppenidentitäten und Berechtigungen. Dieses Token enthält auch eine Anmeldesicherheit-ID (SID), die die Sitzung eindeutig identifiziert.

Die Local Security Authority (LSASS) verarbeitet Zugriffsanforderungen für Objekte, indem sie die DACL auf ACEs überprüft, die mit dem Sicherheitsprinzipal übereinstimmen, der auf den Zugriff zugreift. Der Zugriff wird sofort gewährt, wenn keine relevanten ACEs gefunden werden. Andernfalls vergleicht LSASS die ACEs mit der SID des Sicherheitsprinzipals im Zugriffstoken, um die Zugangsberechtigung zu bestimmen.

### **Zusammengefasster Prozess**

* **ACLs:** Definieren Zugriffsberechtigungen durch DACLs und Überwachungsregeln durch SACLs.
* **Zugriffstoken:** Enthält Benutzer-, Gruppen- und Berechtigungsinformationen für eine Sitzung.
* **Zugriffsentscheidung:** Wird durch den Vergleich der DACL-ACEs mit dem Zugriffstoken getroffen; SACLs werden zur Überwachung verwendet.

### ACEs

Es gibt **drei Haupttypen von Zugriffskontrolleinträgen (ACEs)**:

* **Access Denied ACE**: Dieser ACE verweigert ausdrücklich den Zugriff auf ein Objekt für bestimmte Benutzer oder Gruppen (in einer DACL).
* **Access Allowed ACE**: Dieser ACE gewährt ausdrücklich den Zugriff auf ein Objekt für bestimmte Benutzer oder Gruppen (in einer DACL).
* **System Audit ACE**: Innerhalb einer System Access Control List (SACL) positioniert, ist dieser ACE verantwortlich für die Erstellung von Prüfprotokollen bei Zugriffsversuchen auf ein Objekt durch Benutzer oder Gruppen. Er dokumentiert, ob der Zugriff erlaubt oder verweigert wurde und die Art des Zugriffs.

Jeder ACE hat **vier kritische Komponenten**:

1. Die **Sicherheitskennung (SID)** des Benutzers oder der Gruppe (oder deren Hauptname in einer grafischen Darstellung).
2. Ein **Flag**, das den ACE-Typ identifiziert (Zugriff verweigert, erlaubt oder Systemaudit).
3. **Vererbungsflags**, die bestimmen, ob untergeordnete Objekte den ACE von ihrem übergeordneten Objekt erben können.
4. Eine [**Zugriffsmaske**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), ein 32-Bit-Wert, der die gewährten Rechte des Objekts angibt.

Die Zugriffsbestimmung erfolgt durch die sequentielle Überprüfung jedes ACE, bis:

* Ein **Access-Denied ACE** ausdrücklich die angeforderten Rechte für einen Treuhänder im Zugriffstoken verweigert.
* **Access-Allowed ACE(s)** ausdrücklich alle angeforderten Rechte für einen Treuhänder im Zugriffstoken gewähren.
* Nach der Überprüfung aller ACEs, wenn kein angefordertes Recht **ausdrücklich erlaubt** wurde, wird der Zugriff implizit **verweigert**.

### Reihenfolge der ACEs

Die Art und Weise, wie **ACEs** (Regeln, die sagen, wer auf etwas zugreifen kann oder nicht) in einer Liste namens **DACL** angeordnet sind, ist sehr wichtig. Dies liegt daran, dass das System, sobald es den Zugriff basierend auf diesen Regeln gewährt oder verweigert, aufhört, die restlichen zu überprüfen.

Es gibt eine beste Möglichkeit, diese ACEs zu organisieren, und sie wird als **"kanonische Reihenfolge"** bezeichnet. Diese Methode hilft sicherzustellen, dass alles reibungslos und fair funktioniert. So geht es für Systeme wie **Windows 2000** und **Windows Server 2003**:

* Zuerst alle Regeln, die **speziell für dieses Element** erstellt wurden, vor die, die von woanders stammen, wie einem übergeordneten Ordner.
* In diesen spezifischen Regeln die, die **"nein" (verweigern)** sagen, vor die, die **"ja" (erlauben)** sagen.
* Für die Regeln, die von woanders stammen, beginnen Sie mit denjenigen aus der **nächsten Quelle**, wie dem übergeordneten, und gehen Sie dann von dort zurück. Wiederum **"nein"** vor **"ja."**

Diese Anordnung hilft auf zwei große Arten:

* Sie stellt sicher, dass, wenn es ein spezifisches **"nein"** gibt, es respektiert wird, egal welche anderen **"ja"-Regeln** vorhanden sind.
* Sie ermöglicht es dem Eigentümer eines Elements, das **letzte Wort** darüber zu haben, wer Zugang erhält, bevor irgendwelche Regeln von übergeordneten Ordnern oder weiter zurück in Kraft treten.

Durch diese Vorgehensweise kann der Eigentümer einer Datei oder eines Ordners sehr präzise festlegen, wer Zugang erhält, und sicherstellen, dass die richtigen Personen Zugang haben und die falschen nicht.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

So geht es bei dieser **"kanonischen Reihenfolge"** darum, sicherzustellen, dass die Zugriffsregeln klar und gut funktionieren, spezifische Regeln zuerst zu setzen und alles auf intelligente Weise zu organisieren.

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### GUI-Beispiel

[**Beispiel von hier**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Dies ist die klassische Sicherheitseinstellung eines Ordners, die die ACL, DACL und ACEs zeigt:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Wenn wir auf die **Erweitert-Taste** klicken, erhalten wir weitere Optionen wie Vererbung:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Und wenn Sie einen Sicherheitsprinzipal hinzufügen oder bearbeiten:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Und zuletzt haben wir die SACL im Überwachungs-Tab:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Erklärung der Zugriffskontrolle auf vereinfachte Weise

Bei der Verwaltung des Zugriffs auf Ressourcen, wie einen Ordner, verwenden wir Listen und Regeln, die als Zugriffskontrolllisten (ACLs) und Zugriffskontrolleinträge (ACEs) bekannt sind. Diese definieren, wer auf bestimmte Daten zugreifen kann oder nicht.

#### Zugriff für eine bestimmte Gruppe verweigern

Stellen Sie sich vor, Sie haben einen Ordner namens Kosten, und Sie möchten, dass jeder darauf zugreifen kann, außer dem Marketingteam. Durch die korrekte Einrichtung der Regeln können wir sicherstellen, dass dem Marketingteam ausdrücklich der Zugriff verweigert wird, bevor allen anderen der Zugriff erlaubt wird. Dies geschieht, indem die Regel, die den Zugriff für das Marketingteam verweigert, vor der Regel platziert wird, die den Zugriff für alle erlaubt.

#### Zugriff für ein bestimmtes Mitglied einer verweigerten Gruppe erlauben

Angenommen, Bob, der Marketingleiter, benötigt Zugriff auf den Kostenordner, obwohl das Marketingteam im Allgemeinen keinen Zugriff haben sollte. Wir können eine spezifische Regel (ACE) für Bob hinzufügen, die ihm Zugriff gewährt, und sie vor der Regel platzieren, die den Zugriff für das Marketingteam verweigert. Auf diese Weise erhält Bob Zugriff, trotz der allgemeinen Einschränkung für sein Team.

#### Verständnis der Zugriffskontrolleinträge

ACEs sind die einzelnen Regeln in einer ACL. Sie identifizieren Benutzer oder Gruppen, geben an, welcher Zugriff erlaubt oder verweigert wird, und bestimmen, wie diese Regeln auf Unterelemente angewendet werden (Vererbung). Es gibt zwei Haupttypen von ACEs:

* **Generische ACEs**: Diese gelten allgemein und betreffen entweder alle Arten von Objekten oder unterscheiden nur zwischen Containern (wie Ordnern) und Nicht-Containern (wie Dateien). Zum Beispiel eine Regel, die Benutzern erlaubt, den Inhalt eines Ordners zu sehen, aber nicht auf die darin enthaltenen Dateien zuzugreifen.
* **Objektspezifische ACEs**: Diese bieten eine genauere Kontrolle, indem sie Regeln für spezifische Arten von Objekten oder sogar einzelne Eigenschaften innerhalb eines Objekts festlegen. Zum Beispiel könnte in einem Verzeichnis von Benutzern eine Regel es einem Benutzer erlauben, seine Telefonnummer zu aktualisieren, aber nicht seine Anmeldezeiten.

Jeder ACE enthält wichtige Informationen wie, auf wen die Regel zutrifft (unter Verwendung einer Sicherheitskennung oder SID), was die Regel erlaubt oder verweigert (unter Verwendung einer Zugriffsmaske) und wie sie von anderen Objekten vererbt wird.

#### Wichtige Unterschiede zwischen ACE-Typen

* **Generische ACEs** sind für einfache Zugriffskontrollszenarien geeignet, bei denen dieselbe Regel auf alle Aspekte eines Objekts oder auf alle Objekte innerhalb eines Containers zutrifft.
* **Objektspezifische ACEs** werden für komplexere Szenarien verwendet, insbesondere in Umgebungen wie Active Directory, wo Sie möglicherweise den Zugriff auf spezifische Eigenschaften eines Objekts unterschiedlich steuern müssen.

Zusammenfassend helfen ACLs und ACEs, präzise Zugriffskontrollen zu definieren, um sicherzustellen, dass nur die richtigen Personen oder Gruppen Zugriff auf sensible Informationen oder Ressourcen haben, mit der Möglichkeit, die Zugriffsrechte bis auf die Ebene einzelner Eigenschaften oder Objekttypen anzupassen.

### Layout der Zugriffskontrolleinträge

| ACE-Feld    | Beschreibung                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Typ         | Flag, das den Typ des ACE angibt. Windows 2000 und Windows Server 2003 unterstützen sechs Typen von ACE: Drei generische ACE-Typen, die an alle sicherbaren Objekte angehängt sind. Drei objektspezifische ACE-Typen, die für Active Directory-Objekte auftreten können.                                                                                                                                                                                                                                                            |
| Flags       | Eine Reihe von Bit-Flags, die Vererbung und Überwachung steuern.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Größe       | Anzahl der Bytes an Speicher, die für den ACE zugewiesen sind.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Zugriffsmaske | 32-Bit-Wert, dessen Bits den Zugriffsrechten für das Objekt entsprechen. Bits können entweder ein- oder ausgeschaltet werden, aber die Bedeutung der Einstellung hängt vom ACE-Typ ab. Wenn beispielsweise das Bit, das dem Recht entspricht, Berechtigungen zu lesen, eingeschaltet ist und der ACE-Typ Verweigern ist, verweigert der ACE das Recht, die Berechtigungen des Objekts zu lesen. Wenn dasselbe Bit eingeschaltet ist, der ACE-Typ jedoch Erlauben ist, gewährt der ACE das Recht, die Berechtigungen des Objekts zu lesen. Weitere Details zur Zugriffsmaske erscheinen in der nächsten Tabelle. |
| SID         | Identifiziert einen Benutzer oder eine Gruppe, deren Zugriff durch diesen ACE kontrolliert oder überwacht wird.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Layout der Zugriffsmaske

| Bit (Bereich) | Bedeutung                            | Beschreibung/Beispiel                       |
| ------------- | ------------------------------------ | ------------------------------------------- |
| 0 - 15        | Objektspezifische Zugriffsrechte    | Daten lesen, Ausführen, Daten anhängen      |
| 16 - 22       | Standardzugriffsrechte               | Löschen, ACL schreiben, Eigentümer schreiben |
| 23            | Kann auf Sicherheits-ACL zugreifen   |                                             |
| 24 - 27       | Reserviert                           |                                             |
| 28            | Generisch ALLE (Lesen, Schreiben, Ausführen) | Alles darunter                             |
| 29            | Generisch Ausführen                  | Alle Dinge, die notwendig sind, um ein Programm auszuführen |
| 30            | Generisch Schreiben                  | Alle Dinge, die notwendig sind, um in eine Datei zu schreiben |
| 31            | Generisch Lesen                     | Alle Dinge, die notwendig sind, um eine Datei zu lesen |

## Referenzen

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

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

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}
