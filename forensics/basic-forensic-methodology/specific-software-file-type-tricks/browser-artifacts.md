# Browser-Artefakte

<details>

<summary>Lernen Sie AWS-Hacking von Grund auf mit <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a>!</summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das [offizielle PEASS & HackTricks-Merchandise](https://peass.creator-spring.com)
- Entdecken Sie [The PEASS Family](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [NFTs](https://opensea.io/collection/the-peass-family)
- Treten Sie der 💬 [Discord-Gruppe](https://discord.gg/hRep4RUj7f) oder der [Telegram-Gruppe](https://t.me/peass) bei oder folgen Sie uns auf Twitter 🐦 [@hacktricks_live](https://twitter.com/hacktricks_live).
- Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die [HackTricks](https://github.com/carlospolop/hacktricks) und [HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Browser-Artefakte <a href="#id-3def" id="id-3def"></a>

Browser-Artefakte umfassen verschiedene Arten von Daten, die von Webbrowsern gespeichert werden, wie z.B. Navigationsverlauf, Lesezeichen und Cache-Daten. Diese Artefakte werden in spezifischen Ordnern im Betriebssystem aufbewahrt, die sich je nach Browser in Ort und Namen unterscheiden, aber im Allgemeinen ähnliche Datentypen speichern.

Hier ist eine Zusammenfassung der häufigsten Browser-Artefakte:

- **Navigationsverlauf**: Verfolgt die Besuche des Benutzers auf Websites, nützlich zur Identifizierung von Besuchen auf bösartigen Websites.
- **Autocomplete-Daten**: Vorschläge basierend auf häufigen Suchanfragen, bieten Einblicke, wenn sie mit dem Navigationsverlauf kombiniert werden.
- **Lesezeichen**: Von Benutzern gespeicherte Websites für schnellen Zugriff.
- **Erweiterungen und Add-Ons**: Vom Benutzer installierte Browser-Erweiterungen oder Add-Ons.
- **Cache**: Speichert Webinhalte (z.B. Bilder, JavaScript-Dateien), um die Ladezeiten von Websites zu verbessern, wertvoll für forensische Analysen.
- **Anmeldungen**: Gespeicherte Anmeldeinformationen.
- **Favicons**: Mit Websites verbundene Symbole, die in Tabs und Lesezeichen angezeigt werden, nützlich für zusätzliche Informationen über Benutzerbesuche.
- **Browser-Sitzungen**: Daten im Zusammenhang mit geöffneten Browsersitzungen.
- **Downloads**: Aufzeichnungen über über den Browser heruntergeladene Dateien.
- **Formulardaten**: In Webformularen eingegebene Informationen, die für zukünftige automatische Vervollständigungsvorschläge gespeichert werden.
- **Thumbnails**: Vorschaubilder von Websites.
- **Custom Dictionary.txt**: Vom Benutzer zum Wörterbuch des Browsers hinzugefügte Wörter.


## Firefox

Firefox organisiert Benutzerdaten in Profilen, die anhand des Betriebssystems an spezifischen Orten gespeichert sind:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Eine `profiles.ini`-Datei in diesen Verzeichnissen listet die Benutzerprofile auf. Die Daten jedes Profils werden in einem Ordner gespeichert, der in der `Path`-Variablen innerhalb von `profiles.ini` benannt ist und sich im selben Verzeichnis wie `profiles.ini` selbst befindet. Wenn der Ordner eines Profils fehlt, wurde er möglicherweise gelöscht.

In jedem Profilordner finden Sie mehrere wichtige Dateien:

- **places.sqlite**: Speichert Verlauf, Lesezeichen und Downloads. Tools wie [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) unter Windows können auf die Verlaufsdaten zugreifen.
- Verwenden Sie spezifische SQL-Abfragen, um Informationen zum Verlauf und zu Downloads zu extrahieren.
- **bookmarkbackups**: Enthält Sicherungskopien von Lesezeichen.
- **formhistory.sqlite**: Speichert Webformulardaten.
- **handlers.json**: Verwaltet Protokoll-Handler.
- **persdict.dat**: Benutzerdefinierte Wörterbuchwörter.
- **addons.json** und **extensions.sqlite**: Informationen zu installierten Add-Ons und Erweiterungen.
- **cookies.sqlite**: Cookie-Speicherung, mit [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) zur Inspektion unter Windows verfügbar.
- **cache2/entries** oder **startupCache**: Cache-Daten, zugänglich über Tools wie [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Speichert Favicons.
- **prefs.js**: Benutzereinstellungen und -präferenzen.
- **downloads.sqlite**: Ältere Downloads-Datenbank, jetzt in places.sqlite integriert.
- **thumbnails**: Vorschaubilder von Websites.
- **logins.json**: Verschlüsselte Anmeldeinformationen.
- **key4.db** oder **key3.db**: Speichert Verschlüsselungsschlüssel zur Sicherung sensibler Informationen.

Darüber hinaus kann die Überprüfung der Anti-Phishing-Einstellungen des Browsers durch die Suche nach `browser.safebrowsing`-Einträgen in `prefs.js` erfolgen, die anzeigen, ob die sicheres Browsen aktiviert oder deaktiviert ist.


Um das Master-Passwort zu entschlüsseln, können Sie [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt) verwenden.\
Mit dem folgenden Skript und Aufruf können Sie eine Passwortdatei zum Brute-Forcing angeben:

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

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chrome speichert Benutzerprofile an spezifischen Speicherorten, abhängig vom Betriebssystem:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

In diesen Verzeichnissen befinden sich die meisten Benutzerdaten in den Ordnern **Default/** oder **ChromeDefaultData/**. Die folgenden Dateien enthalten wichtige Daten:

- **History**: Enthält URLs, Downloads und Suchbegriffe. Unter Windows kann [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) verwendet werden, um die Historie zu lesen. Die Spalte "Transition Type" hat verschiedene Bedeutungen, einschließlich Benutzerklicks auf Links, eingegebene URLs, Formularübermittlungen und Seitenaktualisierungen.
- **Cookies**: Speichert Cookies. Zur Inspektion steht [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) zur Verfügung.
- **Cache**: Enthält zwischengespeicherte Daten. Windows-Benutzer können [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) verwenden, um sie zu inspizieren.
- **Bookmarks**: Benutzer-Lesezeichen.
- **Web Data**: Enthält Formularverlauf.
- **Favicons**: Speichert Website-Favicons.
- **Login Data**: Enthält Anmeldeinformationen wie Benutzernamen und Passwörter.
- **Current Session**/**Current Tabs**: Daten zur aktuellen Browsersitzung und geöffneten Tabs.
- **Last Session**/**Last Tabs**: Informationen zu den während der letzten Sitzung aktiven Websites, bevor Chrome geschlossen wurde.
- **Extensions**: Verzeichnisse für Browser-Erweiterungen und Add-Ons.
- **Thumbnails**: Speichert Website-Vorschaubilder.
- **Preferences**: Eine Datei mit vielen Informationen, einschließlich Einstellungen für Plugins, Erweiterungen, Pop-ups, Benachrichtigungen und mehr.
- **Browser-eigener Phishing-Schutz**: Um zu überprüfen, ob der Phishing-Schutz und der Malware-Schutz aktiviert sind, führen Sie `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` aus. Suchen Sie nach `{"enabled: true,"}` in der Ausgabe.


## **Wiederherstellung von SQLite-Datenbanken**

Wie in den vorherigen Abschnitten zu sehen ist, verwenden sowohl Chrome als auch Firefox **SQLite-Datenbanken**, um die Daten zu speichern. Es ist möglich, **gelöschte Einträge mit dem Tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **oder** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) wiederherzustellen.

## **Internet Explorer 11**

Internet Explorer 11 verwaltet seine Daten und Metadaten an verschiedenen Speicherorten, um die gespeicherten Informationen und die entsprechenden Details leicht zugänglich und verwaltbar zu machen.

### Metadatenspeicherung
Metadaten für Internet Explorer werden in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (wobei VX V01, V16 oder V24 ist) gespeichert. Die Datei `V01.log` kann dabei Abweichungen bei den Änderungszeiten von `WebcacheVX.data` anzeigen, was auf eine Reparatur mit `esentutl /r V01 /d` hinweist. Diese Metadaten, die in einer ESE-Datenbank gehalten werden, können mit Tools wie photorec und [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) wiederhergestellt und inspiziert werden. In der Tabelle **Containers** kann man die spezifischen Tabellen oder Container erkennen, in denen jeder Datensegment gespeichert ist, einschließlich Cache-Details für andere Microsoft-Tools wie Skype.

### Cache-Inspektion
Das Tool [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) ermöglicht die Inspektion des Caches und erfordert den Speicherort des extrahierten Cache-Datenordners. Die Metadaten für den Cache umfassen Dateiname, Verzeichnis, Zugriffszähler, URL-Herkunft und Zeitstempel, die die Erstellungs-, Zugriffs-, Änderungs- und Ablaufzeiten des Caches anzeigen.

### Cookies-Verwaltung
Cookies können mit [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) erkundet werden, wobei Metadaten Namen, URLs, Zugriffszähler und verschiedene zeitbezogene Details umfassen. Persistente Cookies werden in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gespeichert, während Sitzungscookies im Speicher verbleiben.

### Download-Details
Metadaten zu Downloads sind über [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) zugänglich, wobei spezifische Container Daten wie URL, Dateityp und Download-Speicherort enthalten. Die physischen Dateien befinden sich unter `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browserverlauf
Um den Browserverlauf zu überprüfen, kann [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) verwendet werden, wobei der Speicherort der extrahierten Verlaufsdateien und die Konfiguration für Internet Explorer angegeben werden müssen. Die Metadaten hier umfassen Änderungs- und Zugriffszeiten sowie Zugriffszähler. Die Verlaufsdateien befinden sich in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Eingegebene URLs
Eingegebene URLs und ihre Verwendungszuordnungen werden in der Registrierung unter `NTUSER.DAT` unter `Software\Microsoft\InternetExplorer\TypedURLs` und `Software\Microsoft\InternetExplorer\TypedURLsTime` gespeichert. Hier werden die letzten 50 vom Benutzer eingegebenen URLs und ihre letzten Eingabezeiten verfolgt.


## Microsoft Edge

Microsoft Edge speichert Benutzerdaten in `%userprofile%\Appdata\Local\Packages`. Die Pfade für verschiedene Datentypen sind:

- **Profilpfad**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Verlauf, Cookies und Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Einstellungen, Lesezeichen und Leseliste**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Zuletzt aktive Sitzungen**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-Daten werden unter `/Users/$User/Library/Safari` gespeichert. Wichtige Dateien sind:

- **History.db**: Enthält die Tabellen `history_visits` und `history_items` mit URLs und Besuchszeitstempeln. Verwenden Sie `sqlite3`, um Abfragen durchzuführen.
- **Downloads.plist**: Informationen über heruntergeladene Dateien.
- **Bookmarks.plist**: Speichert gebookmarkte URLs.
- **TopSites.plist**: Am häufigsten besuchte Websites.
- **Extensions.plist**: Liste der Safari-Browsererweiterungen. Verwenden Sie `plutil` oder `pluginkit`, um sie abzurufen.
- **UserNotificationPermissions.plist**: Domains, die Benachrichtigungen senden dürfen. Verwenden Sie `plutil`, um sie zu analysieren.
- **LastSession.plist**: Tabs aus der letzten Sitzung. Verwenden Sie `plutil`, um sie zu analysieren.
- **Browser-eigener Phishing-Schutz**: Überprüfen Sie mit `defaults read com.apple.Safari WarnAboutFraud
* Hol dir das [**offizielle PEASS & HackTricks Merch**](https://peass.creator-spring.com)
* Entdecke [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Trete der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei** oder **folge** uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teile deine Hacking-Tricks, indem du Pull Requests an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories sendest.**

</details>
