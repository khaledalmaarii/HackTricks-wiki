# Blaaier Artefakte

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=browser-artifacts) om maklik te bou en **werkvloei te outomatiseer** wat deur die wêreld se **mees gevorderde** gemeenskapstools aangedryf word.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=browser-artifacts" %}

## Blaaier Artefakte <a href="#id-3def" id="id-3def"></a>

Blaaier artefakte sluit verskeie tipes data in wat deur webblaaiers gestoor word, soos navigasiegeskiedenis, boekmerke en kasdata. Hierdie artefakte word in spesifieke vouers binne die bedryfstelsel gehou, wat verskil in ligging en naam oor blaaiers, maar oor die algemeen soortgelyke datatipes stoor.

Hier is 'n opsomming van die mees algemene blaaier artefakte:

* **Navigasiegeskiedenis**: Hou gebruikersbesoeke aan webwerwe dop, nuttig om besoeke aan kwaadwillige webwerwe te identifiseer.
* **Outomatiese Voltooiing Data**: Voorstelle gebaseer op gereelde soektogte, wat insigte bied wanneer dit saam met navigasiegeskiedenis gekombineer word.
* **Boekmerke**: Webwerwe wat deur die gebruiker gestoor is vir vinnige toegang.
* **Uitbreidings en Byvoegings**: Blaaieruitbreidings of byvoegings wat deur die gebruiker geïnstalleer is.
* **Kas**: Stoor webinhoud (bv. beelde, JavaScript-lêers) om webwerf laai tye te verbeter, waardevol vir forensiese analise.
* **Aanmeldings**: Gestoor aanmeldbesonderhede.
* **Favicons**: Ikone wat met webwerwe geassosieer word, wat in oortjies en boekmerke verskyn, nuttig vir addisionele inligting oor gebruikersbesoeke.
* **Blaaier Sessies**: Data verwant aan oop blaaier sessies.
* **Aflaaie**: Rekords van lêers wat deur die blaaier afgelaai is.
* **Vormdata**: Inligting wat in webvorms ingevoer is, gestoor vir toekomstige outomatiese voltooiingsvoorstelle.
* **Miniatuurbeelde**: Voorskoubeelde van webwerwe.
* **Custom Dictionary.txt**: Woorde wat deur die gebruiker aan die blaaier se woordeskat bygevoeg is.

## Firefox

Firefox organiseer gebruikersdata binne profiele, gestoor in spesifieke plekke gebaseer op die bedryfstelsel:

* **Linux**: `~/.mozilla/firefox/`
* **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

'n `profiles.ini` lêer binne hierdie gidse lys die gebruikersprofiele. Elke profiel se data word in 'n vouer gestoor wat in die `Path` veranderlike binne `profiles.ini` genoem word, geleë in dieselfde gids as `profiles.ini` self. As 'n profiel se vouer ontbreek, mag dit verwyder wees.

Binne elke profiel vouer, kan jy verskeie belangrike lêers vind:

* **places.sqlite**: Stoor geskiedenis, boekmerke, en aflaaie. Gereedskap soos [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) op Windows kan toegang tot die geskiedenisdata verkry.
* Gebruik spesifieke SQL navrae om geskiedenis en aflaaie inligting te onttrek.
* **bookmarkbackups**: Bevat rugsteun van boekmerke.
* **formhistory.sqlite**: Stoor webvormdata.
* **handlers.json**: Bestuur protokolhanterings.
* **persdict.dat**: Aangepaste woordeskatwoorde.
* **addons.json** en **extensions.sqlite**: Inligting oor geïnstalleerde byvoegings en uitbreidings.
* **cookies.sqlite**: Koekie berging, met [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) beskikbaar vir inspeksie op Windows.
* **cache2/entries** of **startupCache**: Kasdata, toeganklik deur gereedskap soos [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html).
* **favicons.sqlite**: Stoor favicons.
* **prefs.js**: Gebruikersinstellings en voorkeure.
* **downloads.sqlite**: Ouere aflaaie databasis, nou geïntegreer in places.sqlite.
* **thumbnails**: Webwerf miniatuurbeelde.
* **logins.json**: Geënkripteerde aanmeldinligting.
* **key4.db** of **key3.db**: Stoor enkripsiesleutels om sensitiewe inligting te beveilig.

Boonop kan jy die blaaier se anti-phishing instellings nagaan deur te soek na `browser.safebrowsing` inskrywings in `prefs.js`, wat aandui of veilige blaai funksies geaktiveer of gedeaktiveer is.

Om te probeer om die meesterwagwoord te ontsleutel, kan jy [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt) gebruik\
Met die volgende skrip en oproep kan jy 'n wagwoord lêer spesifiseer om te brute force:

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

Google Chrome stoor gebruikersprofiele in spesifieke plekke gebaseer op die bedryfstelsel:

* **Linux**: `~/.config/google-chrome/`
* **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
* **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Binne hierdie gidse kan die meeste gebruikersdata in die **Default/** of **ChromeDefaultData/** vouers gevind word. Die volgende lêers hou belangrike data:

* **History**: Bevat URL's, aflaaie, en soek sleutelwoorde. Op Windows kan [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) gebruik word om die geskiedenis te lees. Die "Transition Type" kolom het verskeie betekenisse, insluitend gebruikersklieks op skakels, getypte URL's, vormindienings, en bladsy herlaai.
* **Cookies**: Stoor koekies. Vir inspeksie is [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) beskikbaar.
* **Cache**: Hou gekaapte data. Om te inspekteer, kan Windows gebruikers [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html) gebruik.
* **Bookmarks**: Gebruikersboekmerke.
* **Web Data**: Bevat vormgeskiedenis.
* **Favicons**: Stoor webwerf favicons.
* **Login Data**: Sluit aanmeldbesonderhede soos gebruikersname en wagwoorde in.
* **Current Session**/**Current Tabs**: Data oor die huidige blaai sessie en oop oortjies.
* **Last Session**/**Last Tabs**: Inligting oor die webwerwe wat aktief was tydens die laaste sessie voordat Chrome gesluit is.
* **Extensions**: Gidse vir blaaiers uitbreidings en addons.
* **Thumbnails**: Stoor webwerf duimnaels.
* **Preferences**: 'n Lêer ryk aan inligting, insluitend instellings vir plugins, uitbreidings, pop-ups, kennisgewings, en meer.
* **Browser’s built-in anti-phishing**: Om te kontroleer of anti-phishing en malware beskerming geaktiveer is, voer `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` uit. Soek na `{"enabled: true,"}` in die uitvoer.

## **SQLite DB Data Recovery**

Soos jy in die vorige afdelings kan waarneem, gebruik beide Chrome en Firefox **SQLite** databasisse om die data te stoor. Dit is moontlik om **verwyderde inskrywings te herstel met die hulpmiddel** [**sqlparse**](https://github.com/padfoot999/sqlparse) **of** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 bestuur sy data en metadata oor verskeie plekke, wat help om gestoor inligting en sy ooreenstemmende besonderhede te skei vir maklike toegang en bestuur.

### Metadata Storage

Metadata vir Internet Explorer word gestoor in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (met VX wat V01, V16, of V24 is). Saam hiermee kan die `V01.log` lêer wys datums van verandering met `WebcacheVX.data`, wat 'n behoefte aan herstel aandui met `esentutl /r V01 /d`. Hierdie metadata, wat in 'n ESE-databasis gehuisves word, kan herstel en ondersoek word met hulpmiddels soos photorec en [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), onderskeidelik. Binne die **Containers** tabel kan 'n mens die spesifieke tabelle of houers waar elke datasegment gestoor word, onderskei, insluitend cache besonderhede vir ander Microsoft gereedskap soos Skype.

### Cache Inspection

Die [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) hulpmiddel laat vir cache inspeksie toe, wat die cache data ekstraksie vouer plek vereis. Metadata vir cache sluit lêernaam, gids, toegang telling, URL oorsprong, en tydstempels in wat die cache skepping, toegang, verandering, en vervaldatums aandui.

### Cookies Management

Koekies kan ondersoek word met [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), met metadata wat name, URL's, toegang tellings, en verskeie tydverwante besonderhede insluit. Volhoubare koekies word gestoor in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, met sessie koekies wat in geheue woon.

### Download Details

Aflaai metadata is toeganklik via [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), met spesifieke houers wat data soos URL, lêer tipe, en aflaai plek hou. Fisiese lêers kan onder `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` gevind word.

### Browsing History

Om blaai geskiedenis te hersien, kan [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) gebruik word, wat die plek van ekstrakte geskiedenis lêers en konfigurasie vir Internet Explorer vereis. Metadata hier sluit verandering en toegang tye in, saam met toegang tellings. Geskiedenis lêers is geleë in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Getypte URL's en hul gebruik tydstippe word in die register onder `NTUSER.DAT` by `Software\Microsoft\InternetExplorer\TypedURLs` en `Software\Microsoft\InternetExplorer\TypedURLsTime` gestoor, wat die laaste 50 URL's wat deur die gebruiker ingevoer is en hul laaste invoer tye op spoor.

## Microsoft Edge

Microsoft Edge stoor gebruikersdata in `%userprofile%\Appdata\Local\Packages`. Die paaie vir verskillende datatipes is:

* **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
* **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
* **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
* **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
* **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari data word gestoor by `/Users/$User/Library/Safari`. Sleutel lêers sluit in:

* **History.db**: Bevat `history_visits` en `history_items` tabelle met URL's en besoek tydstempels. Gebruik `sqlite3` om te vra.
* **Downloads.plist**: Inligting oor afgelaaide lêers.
* **Bookmarks.plist**: Stoor geboekmerkte URL's.
* **TopSites.plist**: Meest besoekte webwerwe.
* **Extensions.plist**: Lys van Safari blaaiers uitbreidings. Gebruik `plutil` of `pluginkit` om te onttrek.
* **UserNotificationPermissions.plist**: Domeine wat toegelaat word om kennisgewings te stuur. Gebruik `plutil` om te parse.
* **LastSession.plist**: Oortjies van die laaste sessie. Gebruik `plutil` om te parse.
* **Browser’s built-in anti-phishing**: Kontroleer met `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. 'n Antwoord van 1 dui aan dat die funksie aktief is.

## Opera

Opera se data is geleë in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` en deel Chrome se formaat vir geskiedenis en aflaaie.

* **Browser’s built-in anti-phishing**: Verifieer deur te kontroleer of `fraud_protection_enabled` in die Voorkeurlêer op `true` gestel is met behulp van `grep`.

Hierdie paaie en opdragte is noodsaaklik vir toegang tot en begrip van die blaai data wat deur verskillende webblaaiers gestoor word.

## References

* [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
* [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
* [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
* **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=browser-artifacts) om maklik te bou en **werkvloei te outomatiseer** wat deur die wêreld se **mees gevorderde** gemeenskap gereedskap aangedryf word.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=browser-artifacts" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kontroleer die [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PR's in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
