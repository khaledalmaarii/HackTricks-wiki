# ZIP-Tricks

{% hint style="success" %}
Lernen Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}

**Befehlszeilentools** zur Verwaltung von **Zip-Dateien** sind unerlässlich für die Diagnose, Reparatur und das Knacken von Zip-Dateien. Hier sind einige wichtige Dienstprogramme:

- **`unzip`**: Zeigt an, warum eine Zip-Datei möglicherweise nicht dekomprimiert werden kann.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der Felder des Zip-Dateiformats.
- **`zipinfo`**: Listet den Inhalt einer Zip-Datei auf, ohne sie zu extrahieren.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte Zip-Dateien zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool zum Brute-Force-Knacken von Zip-Passwörtern, effektiv für Passwörter bis zu etwa 7 Zeichen.

Die [Spezifikation des Zip-Dateiformats](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) bietet umfassende Details zur Struktur und den Standards von Zip-Dateien.

Es ist wichtig zu beachten, dass passwortgeschützte Zip-Dateien **Dateinamen oder Dateigrößen nicht verschlüsseln**, ein Sicherheitsfehler, der nicht bei RAR- oder 7z-Dateien auftritt, die diese Informationen verschlüsseln. Darüber hinaus sind Zip-Dateien, die mit der älteren ZipCrypto-Methode verschlüsselt sind, anfällig für einen **Klartextangriff**, wenn eine unverschlüsselte Kopie einer komprimierten Datei verfügbar ist. Dieser Angriff nutzt den bekannten Inhalt, um das Passwort der Zip-Datei zu knacken, eine Schwachstelle, die in einem Artikel von [HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) detailliert beschrieben und in [diesem wissenschaftlichen Artikel](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf) weiter erläutert wird. Zip-Dateien, die mit der **AES-256**-Verschlüsselung gesichert sind, sind jedoch immun gegen diesen Klartextangriff, was die Bedeutung der Auswahl sicherer Verschlüsselungsmethoden für sensible Daten zeigt.

## Referenzen
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/) 

{% hint style="success" %}
Lernen Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}
