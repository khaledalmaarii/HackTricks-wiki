# Blaaier Artefakte

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en **outomatiese werkstrome** te bou met behulp van die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Blaaier Artefakte <a href="#id-3def" id="id-3def"></a>

Blaaier artefakte sluit verskillende soorte data in wat deur webblaaier gestoor word, soos navigasiegeskiedenis, bladmerke en kasdata. Hierdie artefakte word in spesifieke lêers binne die bedryfstelsel gehou, wat verskil in ligging en naam oor blaaier, maar oor die algemeen soortgelyke datatipes stoor.

Hier is 'n opsomming van die mees algemene blaaier artefakte:

- **Navigasiegeskiedenis**: Hou by watter webwerwe die gebruiker besoek het, nuttig om besoeke aan skadelike webwerwe te identifiseer.
- **Outomatiese voltooiingsdata**: Voorstelle gebaseer op gereelde soektogte, bied insigte wanneer dit gekombineer word met navigasiegeskiedenis.
- **Bladmerke**: Webwerwe wat deur die gebruiker gestoor is vir vinnige toegang.
- **Uitbreidings en Byvoegings**: Blaaieruitbreidings of byvoegings wat deur die gebruiker geïnstalleer is.
- **Kas**: Stoor webinhoud (bv. beelde, JavaScript-lêers) om webwerflaaitye te verbeter, waardevol vir forensiese analise.
- **Aantekeninge**: Gestoorde aanmeldingslegitimasie.
- **Favicons**: Ikone wat met webwerwe geassosieer word en in blaaierblaaie en bladmerke verskyn, nuttig vir addisionele inligting oor gebruikersbesoeke.
- **Blaaier-sessies**: Data wat verband hou met oop blaaier-sessies.
- **Aflaaiers**: Rekords van lêers wat deur die blaaier afgelaai is.
- **Vormdata**: Inligting wat in webvorms ingevoer is en gestoor word vir toekomstige outomatiese voltooiingsvoorstelle.
- **Duimnaels**: Voorskou-afbeeldings van webwerwe.
- **Custom Dictionary.txt**: Woorde wat deur die gebruiker by die blaaier se woordeboek gevoeg is.


## Firefox

Firefox organiseer gebruikersdata binne profiele, wat in spesifieke liggings volgens die bedryfstelsel gestoor word:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

'n `profiles.ini`-lêer binne hierdie gidslys die gebruikersprofiele. Elke profiel se data word in 'n vouer gestoor wat genoem word in die `Path`-veranderlike binne `profiles.ini`, wat in dieselfde gids as `profiles.ini` self geleë is. As 'n profiel se vouer ontbreek, is dit moontlik uitgevee.

Binne elke profielvouer kan jy verskeie belangrike lêers vind:

- **places.sqlite**: Stoor geskiedenis, bladmerke en aflaaie. Gereedskap soos [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) op Windows kan toegang verkry tot die geskiedenisdata.
- Gebruik spesifieke SQL-navrae om geskiedenis- en aflaaie-inligting te onttrek.
- **bookmarkbackups**: Bevat rugsteun van bladmerke.
- **formhistory.sqlite**: Stoor webvormdata.
- **handlers.json**: Bestuur protokolhanteraars.
- **persdict.dat**: Aangepaste woordeboekwoorde.
- **addons.json** en **extensions.sqlite**: Inligting oor geïnstalleerde byvoegings en uitbreidings.
- **cookies.sqlite**: Koekie-opberging, met [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) beskikbaar vir inspeksie op Windows.
- **cache2/entries** of **startupCache**: Kasdata, toeganklik deur gereedskap soos [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Stoor favicons.
- **prefs.js**: Gebruikersinstellings en voorkeure.
- **downloads.sqlite**: Ouer aflaaie-databasis, nou geïntegreer in places.sqlite.
- **thumbnails**: Webwerf-duimnaels.
- **logins.json**: Versleutelde aanmeldingsinligting.
- **key4.db** of **key3.db**: Stoor versleutelingssleutels vir die beveiliging van sensitiewe inligting.

Daarbenewens kan die blaaier se anti-phishing-instellings nagegaan word deur te soek na `browser.safebrowsing`-inskrywings in `prefs.js`, wat aandui of veilige blaaierfunksies geaktiveer of gedeaktiveer is.


Om te probeer om die meesterwagwoord te ontsluit, kan jy [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt) gebruik.\
Met die volgende skripsie en oproep kan jy 'n wagwoordlêer spesifiseer om kragtig te krag:

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

Google Chrome stoor gebruikersprofielle in spesifieke liggings gebaseer op die bedryfstelsel:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Binne hierdie gids, kan die meeste gebruikersdata gevind word in die **Default/** of **ChromeDefaultData/** gids. Die volgende lêers bevat belangrike data:

- **Geskiedenis**: Bevat URL's, aflaaiers, en soek sleutelwoorde. Op Windows, kan [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) gebruik word om die geskiedenis te lees. Die "Transition Type" kolom het verskillende betekenisse, insluitend gebruiker klieke op skakels, getikte URL's, vorm indienings, en bladsy herlaaiings.
- **Koekies**: Stoor koekies. Vir inspeksie, is [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) beskikbaar.
- **Cache**: Hou gekasde data. Om te inspekteer, kan Windows gebruikers [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) gebruik.
- **Bladmerke**: Gebruiker bladmerke.
- **Web Data**: Bevat vorm geskiedenis.
- **Favicons**: Stoor webwerf favicons.
- **Login Data**: Sluit aanmeldingslegitimasie soos gebruikersname en wagwoorde in.
- **Huidige Sessie**/**Huidige Vlakke**: Data oor die huidige blaaier sessie en oop vlakke.
- **Laaste Sessie**/**Laaste Vlakke**: Inligting oor die webwerwe aktief gedurende die laaste sessie voor Chrome gesluit is.
- **Uitbreidings**: Gids vir blaaier uitbreidings en addons.
- **Duimnaels**: Stoor webwerf duimnaels.
- **Voorkeure**: 'n Lêer ryk aan inligting, insluitend instellings vir plugins, uitbreidings, pop-ups, kennisgewings, en meer.
- **Blaaier se ingeboude anti-phishing**: Om te kyk of anti-phishing en malware beskerming geaktiveer is, voer `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` uit. Kyk vir `{"enabled: true,"}` in die uitset.


## **SQLite DB Data Herwinning**

Soos waargeneem kan word in die vorige afdelings, gebruik beide Chrome en Firefox **SQLite** databasisse om die data te stoor. Dit is moontlik om **verwyderde inskrywings te herwin met behulp van die instrumente** [**sqlparse**](https://github.com/padfoot999/sqlparse) **of** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 bestuur sy data en metadata oor verskillende liggings, wat help om gestoorde inligting en die ooreenstemmende besonderhede te skei vir maklike toegang en bestuur.

### Metadata Berging
Metadata vir Internet Explorer word gestoor in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (met VX wat V01, V16, of V24 kan wees). Tesame hiermee, kan die `V01.log` lêer wysigingstyd afwykings met `WebcacheVX.data` toon, wat dui op 'n behoefte vir herstel met behulp van `esentutl /r V01 /d`. Hierdie metadata, wat in 'n ESE databasis gehuisves word, kan herwin en ondersoek word met behulp van instrumente soos photorec en [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) onderskeidelik. Binne die **Containers** tabel, kan 'n mens die spesifieke tabelle of houers waar elke data segment gestoor word, onderskei, insluitend cache besonderhede vir ander Microsoft gereedskap soos Skype.

### Cache Inspeksie
Die [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) instrument maak dit moontlik om die cache te inspekteer, met die vereiste van die cache data onttrekkingsgids. Metadata vir die cache sluit lêernaam, gids, toegangstellings, URL oorsprong, en tydstempels wat cache skepping, toegang, wysiging, en verval tyd aandui.

### Koekies Bestuur
Koekies kan ondersoek word met behulp van [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), met metadata wat name, URL's, toegangstellings, en verskeie tydverwante besonderhede insluit. Volgehoue koekies word gestoor in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, met sessie koekies wat in die geheue bly.

### Aflaaibesonderhede
Aflaaibesonderhede is toeganklik via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), met spesifieke houers wat data soos URL, lêertipe, en aflaaigids bevat. Fisiese lêers kan gevind word onder `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Blaai Geskiedenis
Om blaai geskiedenis te hersien, kan [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gebruik word, met die vereiste van die ligging van die uitgepakte geskiedenis lêers en konfigurasie vir Internet Explorer. Metadata hier sluit wysiging en toegangstye in, tesame met toegangstellings. Geskiedenis lêers is geleë in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Getikte URL's
Getikte URL's en hul gebruikstye word binne die register gestoor onder `NTUSER.DAT` by `Software\Microsoft\InternetExplorer\TypedURLs` en `Software\Microsoft\InternetExplorer\TypedURLsTime`, wat die laaste 50 URL's wat deur die gebruiker ingevoer is en hul laaste inset tye volg.


## Microsoft Edge

Microsoft Edge stoor gebruikersdata in `%userprofile%\Appdata\Local\Packages`. Die paaie vir verskillende datatipes is:

- **Profiel Pad**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Geskiedenis, Koekies, en Aflaaibestande**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Instellings, Bladmerke, en Leeslys**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Laaste Aktiewe Sessies**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari data word gestoor by `/Users/$User/Library/Safari`. Sleutellêers sluit in:

- **History.db**: Bevat `history_visits` en `history_items` tabelle met URL's en besoek tydstempels. Gebruik `sqlite3` om navrae te doen.
- **Downloads.plist**: Inligting oor afgelaai lêers.
- **Bookmarks.plist**: Stoor gebl
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking truuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
