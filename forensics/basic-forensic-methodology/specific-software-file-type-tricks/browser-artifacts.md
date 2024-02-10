# Artifakti pregledača

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** uz pomoć najnaprednijih alata zajednice na svetu.\
Danas dobijte pristup:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artifakti pregledača <a href="#id-3def" id="id-3def"></a>

Artifakti pregledača uključuju različite vrste podataka koje čuvaju veb pregledači, kao što su istorija navigacije, obeleživači i keš podaci. Ovi artifakti se čuvaju u određenim fasciklama unutar operativnog sistema, razlikujući se po lokaciji i imenu u različitim pregledačima, ali uglavnom čuvajući slične vrste podataka.

Evo sažetka najčešćih artifakata pregledača:

- **Istorija navigacije**: Prati posete korisnika veb sajtovima, korisno za identifikaciju poseta zlonamernim sajtovima.
- **Podaci za automatsko popunjavanje**: Predlozi na osnovu čestih pretraga, pružajući uvide kada se kombinuju sa istorijom navigacije.
- **Obeleživači**: Sajtovi koje je korisnik sačuvao radi brzog pristupa.
- **Proširenja i dodaci**: Proširenja pregledača ili dodaci instalirani od strane korisnika.
- **Keš**: Čuva veb sadržaj (npr. slike, JavaScript fajlove) radi poboljšanja vremena učitavanja sajtova, vredno za forenzičku analizu.
- **Prijave**: Sačuvani podaci za prijavljivanje.
- **Favikoni**: Ikone povezane sa veb sajtovima, prikazuju se na karticama i obeleživačima, korisne za dodatne informacije o posetama korisnika.
- **Sesije pregledača**: Podaci vezani za otvorene sesije pregledača.
- **Preuzimanja**: Zapisi o fajlovima preuzetim putem pregledača.
- **Podaci o obrascima**: Informacije unete u veb obrasce, sačuvane za buduće predloge automatskog popunjavanja.
- **Sličice**: Prikazne slike veb sajtova.
- **Custom Dictionary.txt**: Reči dodate od strane korisnika u rečnik pregledača.


## Firefox

Firefox organizuje korisničke podatke unutar profila, koji se čuvaju na određenim lokacijama u zavisnosti od operativnog sistema:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

U direktorijumima se nalazi `profiles.ini` fajl koji sadrži profile korisnika. Podaci svakog profila se čuvaju u fascikli čije ime odgovara vrednosti `Path` promenljive unutar `profiles.ini`, a nalazi se u istom direktorijumu kao i sam `profiles.ini`. Ako fascikla profila nedostaje, možda je obrisana.

Unutar svake fascikle profila, možete pronaći nekoliko važnih fajlova:

- **places.sqlite**: Čuva istoriju, obeleživače i preuzimanja. Alati poput [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) na Windows-u mogu pristupiti podacima istorije.
- Koristite specifične SQL upite za izvlačenje informacija o istoriji i preuzimanjima.
- **bookmarkbackups**: Sadrži rezervne kopije obeleživača.
- **formhistory.sqlite**: Čuva podatke o veb obrascima.
- **handlers.json**: Upravljači protokola.
- **persdict.dat**: Reči prilagođenog rečnika.
- **addons.json** i **extensions.sqlite**: Informacije o instaliranim dodacima i proširenjima.
- **cookies.sqlite**: Skladište kolačića, sa [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) dostupnim za pregled na Windows-u.
- **cache2/entries** ili **startupCache**: Keš podaci, dostupni putem alata poput [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Čuva favikone.
- **prefs.js**: Korisnička podešavanja i preferencije.
- **downloads.sqlite**: Starija baza podataka preuzimanja, sada integrisana u places.sqlite.
- **thumbnails**: Sličice veb sajtova.
- **logins.json**: Šifrovani podaci za prijavljivanje.
- **key4.db** ili **key3.db**: Čuva ključeve za šifrovanje osetljivih informacija.

Dodatno, proveru postavki protiv-fisinga pregledača možete izvršiti pretragom unosa `browser.safebrowsing` u `prefs.js`, što ukazuje da li su funkcije sigurnog pregledanja omogućene ili onemogućene.


Da biste pokušali dešifrovanje glavne lozinke, možete koristiti [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
Pomoću sledećeg skripta i poziva možete specificirati fajl sa lozinkom za brute force:

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

Google Chrome čuva korisničke profile na određenim lokacijama zavisno od operativnog sistema:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

U ovim direktorijumima, većina korisničkih podataka se može naći u fasciklama **Default/** ili **ChromeDefaultData/**. Sledeći fajlovi sadrže značajne podatke:

- **History**: Sadrži URL-ove, preuzimanja i ključne reči pretrage. Na Windows-u, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) se može koristiti za čitanje istorije. Kolona "Transition Type" ima različita značenja, uključujući korisničke klikove na linkove, unete URL-ove, podnesene forme i osvežavanje stranica.
- **Cookies**: Čuva kolačiće. Za pregled, dostupan je [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Čuva keširane podatke. Windows korisnici mogu koristiti [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) za pregled.
- **Bookmarks**: Korisnički obeleživači.
- **Web Data**: Sadrži istoriju formi.
- **Favicons**: Čuva favicon-e veb sajtova.
- **Login Data**: Uključuje korisničke podatke za prijavljivanje kao što su korisnička imena i lozinke.
- **Current Session**/**Current Tabs**: Podaci o trenutnoj sesiji pretraživanja i otvorenim karticama.
- **Last Session**/**Last Tabs**: Informacije o sajtovima aktivnim tokom poslednje sesije pre nego što je Chrome zatvoren.
- **Extensions**: Direktorijumi za proširenja i dodatke pregledača.
- **Thumbnails**: Čuva sličice veb sajtova.
- **Preferences**: Fajl bogat informacijama, uključujući podešavanja za dodatke, proširenja, iskačuće prozore, obaveštenja i još mnogo toga.
- **Ugrađena anti-phishing zaštita pregledača**: Da biste proverili da li je anti-phishing i zaštita od malvera omogućena, pokrenite `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Potražite `{"enabled: true,"}` u izlazu.


## **Obnova podataka iz SQLite baze**

Kao što možete primetiti u prethodnim odeljcima, i Chrome i Firefox koriste **SQLite** baze podataka za čuvanje podataka. Moguće je **obnoviti obrisane unose koristeći alat** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ili** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 upravlja svojim podacima i metapodacima na različitim lokacijama, olakšavajući razdvajanje čuvanih informacija i odgovarajućih detalja radi lakšeg pristupa i upravljanja.

### Čuvanje metapodataka
Metapodaci za Internet Explorer se čuvaju u `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (pri čemu je VX V01, V16 ili V24). Uz to, fajl `V01.log` može pokazivati neslaganja u vremenu izmene sa `WebcacheVX.data`, što ukazuje na potrebu za popravkom korišćenjem `esentutl /r V01 /d`. Ovi metapodaci, smešteni u ESE bazi podataka, mogu se obnoviti i pregledati pomoću alata kao što su photorec i [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). U okviru tabele **Containers**, moguće je razlikovati specifične tabele ili kontejnere u kojima se čuva svaki segment podataka, uključujući detalje keša za druge Microsoft alate kao što je Skype.

### Pregled keša
Alat [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) omogućava pregled keša, uz zahtev za lokacijom fascikle za ekstrakciju podataka iz keša. Metapodaci za keš uključuju ime fajla, direktorijum, broj pristupa, URL poreklo i vremenske oznake koje ukazuju na vreme kreiranja, pristupa, izmene i isteka keša.

### Upravljanje kolačićima
Kolačiće je moguće istražiti pomoću [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), pri čemu metapodaci obuhvataju imena, URL-ove, broj pristupa i razne detalje vezane za vreme. Trajni kolačići se čuvaju u `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, dok se sesijski kolačići čuvaju u memoriji.

### Detalji preuzimanja
Metapodaci o preuzimanjima su dostupni putem [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), pri čemu specifični kontejneri sadrže podatke poput URL-a, tipa fajla i lokacije preuzimanja. Fizički fajlovi se mogu pronaći pod `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Istorija pretraživanja
Za pregled istorije pretraživanja može se koristiti [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), uz zahtev za lokacijom izdvojenih fajlova istorije i konfiguracijom za Internet Explorer. Metapodaci ovde uključuju vreme izmene i pristupa, zajedno sa brojem pristupa. Fajlovi istorije se nalaze u `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Uneti URL-ovi
Uneti URL-ovi i vremena njihove upotrebe se čuvaju u registru pod `NTUSER.DAT` na lokaciji `Software\Microsoft\InternetExplorer\TypedURLs` i `Software\Microsoft\InternetExplorer\TypedURLsTime`, prateći poslednjih 50 URL-ova unetih od strane korisnika i njihova poslednja vremena unosa.


## Microsoft Edge

Microsoft Edge čuva korisničke podatke u `%userprofile%\Appdata\Local\Packages`. Putanje za različite vrste podataka su:

- **Putanja profila**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Istorija, kolačići i preuzimanja**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Podešavanja, obeleživači i lista za čitanje**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan
* Nabavite [**zvanični PEASS & HackTricks suvenir**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
