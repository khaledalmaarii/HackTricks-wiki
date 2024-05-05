# Browser Artefakte

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **outomatiseer werkstrome** aangedryf deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandaag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Browser Artefakte <a href="#id-3def" id="id-3def"></a>

Browser artefakte sluit verskeie soorte data in wat deur webblaaier gestoor word, soos navigasiegeskiedenis, bladmerke en tuisbladdata. Hierdie artefakte word in spesifieke velde binne die bedryfstelsel gehou, wat verskil in ligging en naam oor blaaier, maar oor die algemeen soortgelyke datatipes stoor.

Hier is 'n opsomming van die mees algemene blaaier artefakte:

* **Navigasiegeskiedenis**: Spoor gebruikersbesoeke aan webwerwe, nuttig vir die identifisering van besoeke aan skadelike webwerwe.
* **Outomatiese Data**: Voorstelle gebaseer op gereelde soektogte, bied insigte wanneer dit gekombineer word met navigasiegeskiedenis.
* **Bladmerke**: Webwerwe wat deur die gebruiker gestoor is vir vinnige toegang.
* **Uitbreidings en Byvoegings**: Blaaieruitbreidings of byvoegings wat deur die gebruiker geïnstalleer is.
* **Tuisblad**: Stoor webinhoud (bv. afbeeldings, JavaScript-lêers) om webwerf-laaitye te verbeter, waardevol vir forensiese analise.
* **Aantekeninge**: Gestoorde aanmeldingslegitimasie.
* **Favicons**: Ikone wat met webwerwe geassosieer word, verskyn in lêers en bladmerke, nuttig vir addisionele inligting oor gebruikersbesoeke.
* **Blaaier-sessies**: Data wat verband hou met oop blaaier-sessies.
* **Aflaaie**: Rekords van lêers wat deur die blaaier afgelaai is.
* **Vormdata**: Inligting wat in webvorms ingevoer is, gestoor vir toekomstige outomatiese voorstelle.
* **Duimnaels**: Voorskou-afbeeldings van webwerwe.
* **Aangepaste Woordeboek.txt**: Woorde wat deur die gebruiker by die blaaier se woordeboek gevoeg is.

## Firefox

Firefox organiseer gebruikersdata binne profiele, gestoor op spesifieke ligginge gebaseer op die bedryfstelsel:

* **Linux**: `~/.mozilla/firefox/`
* **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**: `%userprofile%\AppData\Roaming/Mozilla/Firefox/Profiles/`

'n `profiles.ini`-lêer binne hierdie gide lys die gebruikersprofiele. Elke profiel se data word gestoor in 'n vouer genoem in die `Path`-veranderlike binne `profiles.ini`, geleë in dieselfde gids as `profiles.ini` self. As 'n profiel se vouer ontbreek, mag dit verwyder wees.

Binne elke profielvouer kan jy verskeie belangrike lêers vind:

* **places.sqlite**: Stoor geskiedenis, bladmerke en aflaaie. Gereedskap soos [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) op Windows kan toegang verkry tot die geskiedenisdata.
* Gebruik spesifieke SQL-navrae om geskiedenis- en aflaaie-inligting te onttrek.
* **bookmarkbackups**: Bevat rugsteun van bladmerke.
* **formhistory.sqlite**: Stoor webvormdata.
* **handlers.json**: Bestuur protokolhanterings.
* **persdict.dat**: Aangepaste woordeboekwoorde.
* **addons.json** en **extensions.sqlite**: Inligting oor geïnstalleerde byvoegings en uitbreidings.
* **cookies.sqlite**: Koekie-opberging, met [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) beskikbaar vir inspeksie op Windows.
* **cache2/entries** of **startupCache**: Tuisbladdata, toeganklik deur gereedskap soos [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html).
* **favicons.sqlite**: Stoor favicons.
* **prefs.js**: Gebruikersinstellings en voorkeure.
* **downloads.sqlite**: Ouer aflaaie-databasis, nou geïntegreer in places.sqlite.
* **thumbnails**: Webwerfduimnaels.
* **logins.json**: Versleutelde aanmeldingsinligting.
* **key4.db** of **key3.db**: Stoor versleutelingssleutels vir die beveiliging van sensitiewe inligting.

Daarbenewens kan die blaaier se teen-phishing-instellings nagegaan word deur te soek na `browser.safebrowsing`-inskrywings in `prefs.js`, wat aandui of veilige blaai-funksies geaktiveer of gedeaktiveer is.

Om te probeer om die meesterwagwoord te ontsluit, kan jy [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt) gebruik\
Met die volgende skripsie en oproep kan jy 'n wagwoordlêer spesifiseer om krag te gebruik:
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

Google Chrome stoor gebruikersprofiele op spesifieke plekke gebaseer op die bedryfstelsel:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Binne hierdie gids kan die meeste gebruikersdata gevind word in die **Default/** of **ChromeDefaultData/** vouers. Die volgende lêers bevat belangrike data:

- **Geskiedenis**: Bevat URL's, aflaaie, en soek sleutelwoorde. Op Windows kan [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) gebruik word om die geskiedenis te lees. Die "Oorgangstipe" kolom het verskeie betekenisse, insluitend gebruikersklikke op skakels, getikte URL's, vorm indienings, en bladsy herlaaiings.
- **Koekies**: Stoor koekies. Vir inspeksie is [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) beskikbaar.
- **Cache**: Hou gekaapte data. Windows gebruikers kan [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html) gebruik vir inspeksie.
- **Bladmerke**: Gebruiker bladmerke.
- **Web Data**: Bevat vorm geskiedenis.
- **Favicons**: Stoor webwerf favicons.
- **Aantekeningsdata**: Sluit aanmeldingsinligting soos gebruikersname en wagwoorde in.
- **Huidige Sessie**/**Huidige Lappe**: Data oor die huidige blaai sessie en oop lappe.
- **Laaste Sessie**/**Laaste Lappe**: Inligting oor die webwerwe aktief tydens die laaste sessie voor Chrome gesluit is.
- **Uitbreidings**: Gidse vir blaaier uitbreidings en byvoegings.
- **Duimnaels**: Stoor webwerf duimnaels.
- **Voorkeure**: 'n Lêer ryk aan inligting, insluitend instellings vir proppe, uitbreidings, pop-ups, kennisgewings, en meer.
- **Blaaier se ingeboude teen-phishing**: Om te kontroleer of teen-phishing en kwaadwillige beskerming geaktiveer is, hardloop `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Soek na `{"geaktiveer: waar,"}` in die uitset.

## **SQLite DB Data Herwinning**

Soos waargeneem kan word in die vorige afdelings, gebruik beide Chrome en Firefox **SQLite** databasisse om die data te stoor. Dit is moontlik om **verwyderde inskrywings te herwin met die hulpmiddel** [**sqlparse**](https://github.com/padfoot999/sqlparse) **of** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 bestuur sy data en metadata oor verskeie plekke, wat help om gestoorde inligting en die ooreenstemmende besonderhede te skei vir maklike toegang en bestuur.

### Metadata Berging

Metadata vir Internet Explorer word gestoor in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (met VX wat V01, V16, of V24 kan wees). Saam met dit, kan die `V01.log` lêer wysigingstyd diskrepansies met `WebcacheVX.data` toon, wat 'n behoefte vir herstel met `esentutl /r V01 /d` aandui. Hierdie metadata, gehuisves in 'n ESE databasis, kan herwin en ondersoek word met hulpmiddels soos photorec en [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) onderskeidelik. Binne die **Containers** tabel, kan 'n persoon die spesifieke tabelle of houers onderskei waar elke data segment gestoor word, insluitend cache besonderhede vir ander Microsoft gereedskap soos Skype.

### Cache Inspeksie

Die [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) hulpmiddel maak voorsiening vir cache inspeksie, wat die lokasie van die cache data ekstraksie vouer benodig. Metadata vir die cache sluit lêernaam, gids, toegangstelling, URL oorsprong, en tydstempels wat cache skepping, toegang, wysiging, en verval tyd aandui.

### Koekies Bestuur

Koekies kan ondersoek word met [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), met metadata wat name, URL's, toegangstellings, en verskeie tydverwante besonderhede insluit. Volgehoue koekies word gestoor in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, met sessie koekies wat in die geheue bly.

### Aflaaibesonderhede

Aflaaibesonderhede is toeganklik via [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), met spesifieke houers wat data soos URL, lêertipe, en aflaaiplek bevat. Fisiese lêers kan gevind word onder `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Blaai Geskiedenis

Om blaai geskiedenis te hersien, kan [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) gebruik word, wat die lokasie van die geëkstraeerde geskiedenis lêers en konfigurasie vir Internet Explorer benodig. Metadata hier sluit wysiging en toegangstye in, saam met toegangstellings. Geskiedenis lêers is geleë in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Getikte URL's

Getikte URL's en hul gebruikstye word binne die register gestoor onder `NTUSER.DAT` by `Software\Microsoft\InternetExplorer\TypedURLs` en `Software\Microsoft\InternetExplorer\TypedURLsTime`, wat die laaste 50 URL's aangedui deur die gebruiker en hul laaste insettye volg.

## Microsoft Edge

Microsoft Edge stoor gebruikersdata in `%userprofile%\Appdata\Local\Packages`. Die paaie vir verskeie datatipes is:

- **Profiel Pad**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Geskiedenis, Koekies, en Aflaaie**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Instellings, Bladmerke, en Leeslys**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Laaste Aktiewe Sessies**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari data word gestoor by `/Users/$User/Library/Safari`. Sleutellêers sluit in:

- **History.db**: Bevat `history_visits` en `history_items` tabelle met URL's en besoek tydstempels. Gebruik `sqlite3` vir navrae.
- **Downloads.plist**: Inligting oor afgelaaide lêers.
- **Bookmarks.plist**: Stoor gebladmerkte URL's.
- **TopSites.plist**: Mees besoekte webwerwe.
- **Extensions.plist**: Lys van Safari blaaier uitbreidings. Gebruik `plutil` of `pluginkit` vir herwinning.
- **UserNotificationPermissions.plist**: Domeine toegelaat om kennisgewings te stuur. Gebruik `plutil` om te ontled.
- **LastSession.plist**: Lappe van die laaste sessie. Gebruik `plutil` om te ontled.
- **Blaaier se ingeboude teen-phishing**: Kontroleer met `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. 'n Antwoord van 1 dui aan dat die funksie aktief is.

## Opera

Opera se data bly in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` en deel Chrome se formaat vir geskiedenis en aflaaie.

- **Blaaier se ingeboude teen-phishing**: Verifieer deur te kyk of `fraud_protection_enabled` in die Voorkeure lêer op `true` gestel is met `grep`.

Hierdie paaie en bevele is noodsaaklik vir die toegang en begrip van die blaai data gestoor deur verskillende webblaaier.
* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks uitrusting**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
