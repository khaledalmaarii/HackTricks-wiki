# Browser-Artefakte

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=browser-artifacts), um mühelos **Workflows zu erstellen und zu automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=browser-artifacts" %}

## Browser-Artefakte <a href="#id-3def" id="id-3def"></a>

Browser-Artefakte umfassen verschiedene Arten von Daten, die von Webbrowsern gespeichert werden, wie Navigationsverlauf, Lesezeichen und Cache-Daten. Diese Artefakte werden in spezifischen Ordnern im Betriebssystem aufbewahrt, unterscheiden sich in Standort und Namen zwischen Browsern, speichern jedoch im Allgemeinen ähnliche Datentypen.

Hier ist eine Zusammenfassung der häufigsten Browser-Artefakte:

* **Navigationsverlauf**: Verfolgt die Besuche von Benutzern auf Websites, nützlich zur Identifizierung von Besuchen auf bösartigen Websites.
* **Automatische Vervollständigung**: Vorschläge basierend auf häufigen Suchanfragen, bieten Einblicke, wenn sie mit dem Navigationsverlauf kombiniert werden.
* **Lesezeichen**: Von Benutzern gespeicherte Websites für schnellen Zugriff.
* **Erweiterungen und Add-ons**: Vom Benutzer installierte Browsererweiterungen oder Add-ons.
* **Cache**: Speichert Webinhalte (z. B. Bilder, JavaScript-Dateien) zur Verbesserung der Ladezeiten von Websites, wertvoll für forensische Analysen.
* **Anmeldungen**: Gespeicherte Anmeldeinformationen.
* **Favicons**: Mit Websites verknüpfte Symbole, die in Registerkarten und Lesezeichen erscheinen, nützlich für zusätzliche Informationen zu Benutzerbesuchen.
* **Browser-Sitzungen**: Daten zu offenen Browsersitzungen.
* **Downloads**: Aufzeichnungen von über den Browser heruntergeladenen Dateien.
* **Formulardaten**: In Webformularen eingegebene Informationen, gespeichert für zukünftige automatische Vervollständigungsvorschläge.
* **Miniaturansichten**: Vorschau-Bilder von Websites.
* **Benutzerdefinierte Wörterbuch.txt**: Vom Benutzer zum Wörterbuch des Browsers hinzugefügte Wörter.

## Firefox

Firefox organisiert Benutzerdaten in Profilen, die an spezifischen Standorten basierend auf dem Betriebssystem gespeichert sind:

* **Linux**: `~/.mozilla/firefox/`
* **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Eine `profiles.ini`-Datei in diesen Verzeichnissen listet die Benutzerprofile auf. Die Daten jedes Profils werden in einem Ordner gespeichert, der im `Path`-Variablen innerhalb von `profiles.ini` benannt ist, der sich im selben Verzeichnis wie `profiles.ini` selbst befindet. Wenn ein Profilordner fehlt, wurde er möglicherweise gelöscht.

In jedem Profilordner finden Sie mehrere wichtige Dateien:

* **places.sqlite**: Speichert Verlauf, Lesezeichen und Downloads. Tools wie [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) unter Windows können auf die Verlaufsdaten zugreifen.
* Verwenden Sie spezifische SQL-Abfragen, um Verlaufs- und Downloadinformationen zu extrahieren.
* **bookmarkbackups**: Enthält Sicherungskopien von Lesezeichen.
* **formhistory.sqlite**: Speichert Webformulardaten.
* **handlers.json**: Verwaltet Protokollhandler.
* **persdict.dat**: Benutzerdefinierte Wörterbuchwörter.
* **addons.json** und **extensions.sqlite**: Informationen zu installierten Add-ons und Erweiterungen.
* **cookies.sqlite**: Cookie-Speicher, mit [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) zur Inspektion unter Windows verfügbar.
* **cache2/entries** oder **startupCache**: Cache-Daten, zugänglich durch Tools wie [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html).
* **favicons.sqlite**: Speichert Favicons.
* **prefs.js**: Benutzereinstellungen und -präferenzen.
* **downloads.sqlite**: Ältere Downloads-Datenbank, jetzt in places.sqlite integriert.
* **thumbnails**: Miniaturansichten von Websites.
* **logins.json**: Verschlüsselte Anmeldeinformationen.
* **key4.db** oder **key3.db**: Speichert Verschlüsselungsschlüssel zur Sicherung sensibler Informationen.

Zusätzlich kann die Überprüfung der Anti-Phishing-Einstellungen des Browsers durch die Suche nach `browser.safebrowsing`-Einträgen in `prefs.js` erfolgen, die anzeigen, ob die Funktionen für sicheres Surfen aktiviert oder deaktiviert sind.

Um zu versuchen, das Masterpasswort zu entschlüsseln, können Sie [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt) verwenden\
Mit dem folgenden Skript und Aufruf können Sie eine Passwortdatei zum Brute-Forcen angeben:

{% code title="brute.sh" %}
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
{% endcode %}

![](<../../../.gitbook/assets/image (692).png>)

## Google Chrome

Google Chrome speichert Benutzerprofile an spezifischen Orten basierend auf dem Betriebssystem:

* **Linux**: `~/.config/google-chrome/`
* **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
* **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

In diesen Verzeichnissen befinden sich die meisten Benutzerdaten in den Ordnern **Default/** oder **ChromeDefaultData/**. Die folgenden Dateien enthalten wichtige Daten:

* **Verlauf**: Enthält URLs, Downloads und Suchbegriffe. Auf Windows kann [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) verwendet werden, um den Verlauf zu lesen. Die Spalte "Transition Type" hat verschiedene Bedeutungen, einschließlich Benutzerklicks auf Links, eingegebene URLs, Formulareingaben und Seitenaktualisierungen.
* **Cookies**: Speichert Cookies. Zur Inspektion steht [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) zur Verfügung.
* **Cache**: Enthält zwischengespeicherte Daten. Windows-Benutzer können zur Inspektion [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html) nutzen.
* **Lesezeichen**: Benutzer-Lesezeichen.
* **Webdaten**: Enthält Formularverlauf.
* **Favicons**: Speichert Website-Favicons.
* **Anmeldedaten**: Enthält Anmeldeinformationen wie Benutzernamen und Passwörter.
* **Aktuelle Sitzung**/**Aktuelle Tabs**: Daten zur aktuellen Browsing-Sitzung und geöffneten Tabs.
* **Letzte Sitzung**/**Letzte Tabs**: Informationen zu den während der letzten Sitzung aktiven Websites, bevor Chrome geschlossen wurde.
* **Erweiterungen**: Verzeichnisse für Browsererweiterungen und Add-Ons.
* **Miniaturansichten**: Speichert Website-Miniaturansichten.
* **Einstellungen**: Eine Datei mit vielen Informationen, einschließlich Einstellungen für Plugins, Erweiterungen, Pop-ups, Benachrichtigungen und mehr.
* **Browser-eigener Anti-Phishing-Schutz**: Um zu überprüfen, ob der Anti-Phishing- und Malware-Schutz aktiviert ist, führen Sie `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` aus. Suchen Sie nach `{"enabled: true,"}` in der Ausgabe.

## **Wiederherstellung von SQLite-DB-Daten**

Wie in den vorherigen Abschnitten zu sehen ist, verwenden sowohl Chrome als auch Firefox **SQLite**-Datenbanken zur Speicherung der Daten. Es ist möglich, **gelöschte Einträge mithilfe des Tools** [**sqlparse**](https://github.com/padfoot999/sqlparse) **oder** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) wiederherzustellen.

## **Internet Explorer 11**

Internet Explorer 11 verwaltet seine Daten und Metadaten an verschiedenen Orten, was die Trennung von gespeicherten Informationen und den entsprechenden Details zur einfachen Zugriff und Verwaltung erleichtert.

### Metadatenspeicherung

Metadaten für Internet Explorer werden in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (wobei VX V01, V16 oder V24 ist) gespeichert. Begleitend dazu kann die Datei `V01.log` Zeitunterschiede zur Änderungszeit von `WebcacheVX.data` aufweisen, was auf eine Reparatur mit `esentutl /r V01 /d` hinweist. Diese Metadaten, die in einer ESE-Datenbank gespeichert sind, können mithilfe von Tools wie photorec und [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) wiederhergestellt und inspiziert werden. In der **Containers**-Tabelle kann man die spezifischen Tabellen oder Container erkennen, in denen jeder Datensegment gespeichert ist, einschließlich Cache-Details für andere Microsoft-Tools wie Skype.

### Cache-Inspektion

Das Tool [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) ermöglicht die Cache-Inspektion und erfordert den Speicherort des Cache-Datenextraktionsordners. Die Metadaten für den Cache enthalten Dateinamen, Verzeichnis, Zugriffszähler, URL-Herkunft und Zeitstempel, die die Erstellung, den Zugriff, die Änderung und das Ablaufdatum des Caches anzeigen.

### Cookies-Verwaltung

Cookies können mithilfe von [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) erkundet werden, wobei Metadaten Namen, URLs, Zugriffszähler und verschiedene zeitbezogene Details umfassen. Persistente Cookies werden unter `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gespeichert, während Sitzungscookies im Speicher verbleiben.

### Download-Details

Download-Metadaten sind über [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) zugänglich, wobei spezifische Container Daten wie URL, Dateityp und Download-Speicherort enthalten. Die physischen Dateien befinden sich unter `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browserverlauf

Um den Browserverlauf zu überprüfen, kann [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) verwendet werden, wobei der Speicherort der extrahierten Verlaufsdateien und die Konfiguration für Internet Explorer erforderlich sind. Die Metadaten enthalten hier Änderungs- und Zugriffszeiten sowie Zugriffszähler. Die Verlaufsdateien befinden sich in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Eingegebene URLs

Eingegebene URLs und deren Verwendungszuordnungen werden in der Registrierung unter `NTUSER.DAT` unter `Software\Microsoft\InternetExplorer\TypedURLs` und `Software\Microsoft\InternetExplorer\TypedURLsTime` gespeichert, wobei die letzten 50 vom Benutzer eingegebenen URLs und deren letzte Eingabezeiten verfolgt werden.

## Microsoft Edge

Microsoft Edge speichert Benutzerdaten in `%userprofile%\Appdata\Local\Packages`. Die Pfade für verschiedene Datentypen lauten:

* **Profilpfad**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
* **Verlauf, Cookies und Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
* **Einstellungen, Lesezeichen und Leseliste**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
* **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
* **Letzte aktive Sitzungen**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-Daten werden unter `/Users/$User/Library/Safari` gespeichert. Wichtige Dateien sind:

* **History.db**: Enthält Tabellen `history_visits` und `history_items` mit URLs und Besuchszeitstempeln. Verwenden Sie `sqlite3` zum Abfragen.
* **Downloads.plist**: Informationen zu heruntergeladenen Dateien.
* **Bookmarks.plist**: Speichert Lesezeichen-URLs.
* **TopSites.plist**: Meistbesuchte Websites.
* **Extensions.plist**: Liste der Safari-Browsererweiterungen. Verwenden Sie `plutil` oder `pluginkit` zum Abrufen.
* **UserNotificationPermissions.plist**: Domains, die Benachrichtigungen senden dürfen. Verwenden Sie `plutil` zum Parsen.
* **LastSession.plist**: Tabs aus der letzten Sitzung. Verwenden Sie `plutil` zum Parsen.
* **Browser-eigener Anti-Phishing-Schutz**: Überprüfen Sie mit `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Eine Antwort von 1 zeigt an, dass die Funktion aktiv ist.

## Opera

Die Daten von Opera befinden sich in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` und entsprechen dem Format von Chrome für Verlauf und Downloads.

* **Browser-eigener Anti-Phishing-Schutz**: Überprüfen Sie, ob `fraud_protection_enabled` in der Preferences-Datei auf `true` gesetzt ist, indem Sie `grep` verwenden.

Diese Pfade und Befehle sind entscheidend für den Zugriff auf und das Verständnis der von verschiedenen Webbrowsern gespeicherten Browsing-Daten.

## Referenzen

* [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
* [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
* [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
* **Buch: OS X Incident Response: Scripting and Analysis By Jaron Bradley Seite 123**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=browser-artifacts), um mithilfe der weltweit **fortschrittlichsten Community-Tools** einfach **Workflows zu erstellen und zu automatisieren**.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=browser-artifacts" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>
* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** möchten oder **HackTricks im PDF-Format herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
