# ZIP-Tricks

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

**Befehlszeilentools** zur Verwaltung von **ZIP-Dateien** sind unerlässlich, um ZIP-Dateien zu diagnostizieren, zu reparieren und zu knacken. Hier sind einige wichtige Dienstprogramme:

- **`unzip`**: Zeigt an, warum eine ZIP-Datei nicht dekomprimiert werden kann.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der Felder des ZIP-Dateiformats.
- **`zipinfo`**: Listet den Inhalt einer ZIP-Datei auf, ohne sie zu extrahieren.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte ZIP-Dateien zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool zum Brute-Force-Knacken von ZIP-Passwörtern, das für Passwörter bis zu etwa 7 Zeichen effektiv ist.

Die [Spezifikation des ZIP-Dateiformats](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) enthält umfassende Details zur Struktur und den Standards von ZIP-Dateien.

Es ist wichtig zu beachten, dass passwortgeschützte ZIP-Dateien **Dateinamen oder Dateigrößen nicht verschlüsseln**, eine Sicherheitslücke, die nicht bei RAR- oder 7z-Dateien gemeinsam ist, die diese Informationen verschlüsseln. Darüber hinaus sind ZIP-Dateien, die mit der älteren Methode ZipCrypto verschlüsselt sind, anfällig für einen **Klartextangriff**, wenn eine unverschlüsselte Kopie einer komprimierten Datei verfügbar ist. Dieser Angriff nutzt den bekannten Inhalt, um das Passwort der ZIP-Datei zu knacken, eine Schwachstelle, die in [HackThis's Artikel](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) detailliert beschrieben und in [diesem wissenschaftlichen Artikel](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf) weiter erläutert wird. ZIP-Dateien, die jedoch mit **AES-256**-Verschlüsselung gesichert sind, sind immun gegen diesen Klartextangriff, was die Bedeutung der Auswahl sicherer Verschlüsselungsmethoden für sensible Daten zeigt.

## Referenzen
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
