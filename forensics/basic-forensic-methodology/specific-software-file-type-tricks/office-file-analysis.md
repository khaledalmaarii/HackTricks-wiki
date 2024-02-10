# Analyse von Office-Dateien

<details>

<summary>Lernen Sie AWS-Hacking von Grund auf mit <a href="https://training.hacktricks.xyz/courses/arte">htARTE (HackTricks AWS Red Team Expert)</a>!</summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das offizielle PEASS & HackTricks-Merchandise
- Entdecken Sie die PEASS-Familie, unsere Sammlung exklusiver NFTs
- Treten Sie der Discord-Gruppe oder der Telegram-Gruppe bei oder folgen Sie uns auf Twitter @hacktricks_live.
- Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zu den HackTricks- und HackTricks Cloud-GitHub-Repositories einreichen.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

Weitere Informationen finden Sie unter [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Hier ist nur eine Zusammenfassung:

Microsoft hat viele Office-Dokumentenformate erstellt, wobei zwei Haupttypen die OLE-Formate (wie RTF, DOC, XLS, PPT) und die Office Open XML (OOXML) Formate (wie DOCX, XLSX, PPTX) sind. Diese Formate können Makros enthalten, wodurch sie zu Zielen für Phishing und Malware werden. OOXML-Dateien sind als Zip-Container strukturiert, die durch Entpacken inspiziert werden können, wodurch die Datei- und Ordnerhierarchie sowie der Inhalt der XML-Dateien sichtbar werden.

Zur Erkundung der OOXML-Dateistrukturen werden der Befehl zum Entpacken eines Dokuments und die Ausgabestruktur angegeben. Techniken zur Versteckung von Daten in diesen Dateien wurden dokumentiert, was auf eine fortlaufende Innovation bei der Datenverdeckung in CTF-Herausforderungen hinweist.

Für die Analyse bieten **oletools** und **OfficeDissector** umfassende Werkzeugsätze zur Untersuchung von OLE- und OOXML-Dokumenten. Diese Tools helfen bei der Identifizierung und Analyse von eingebetteten Makros, die oft als Vektoren für die Bereitstellung von Malware dienen und in der Regel zusätzliche bösartige Nutzlasten herunterladen und ausführen. Die Analyse von VBA-Makros kann ohne Microsoft Office durch Verwendung von Libre Office durchgeführt werden, das das Debuggen mit Breakpoints und Überwachungsvariablen ermöglicht.

Die Installation und Verwendung von **oletools** ist unkompliziert, mit bereitgestellten Befehlen zur Installation über pip und zum Extrahieren von Makros aus Dokumenten. Die automatische Ausführung von Makros wird durch Funktionen wie `AutoOpen`, `AutoExec` oder `Document_Open` ausgelöst.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
