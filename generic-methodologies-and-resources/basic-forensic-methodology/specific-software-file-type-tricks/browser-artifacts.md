# Vifaa vya Kivinjari

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mifumo ya kazi** kwa kutumia zana za **jamii yenye maendeleo zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Vifaa vya Kivinjari <a href="#id-3def" id="id-3def"></a>

Vifaa vya kivinjari ni pamoja na aina mbalimbali za data zilizohifadhiwa na vivinjari vya wavuti, kama historia ya urambazaji, alamisho, na data ya cache. Vifaa hivi vinahifadhiwa katika folda maalum ndani ya mfumo wa uendeshaji, tofauti katika eneo na jina kati ya vivinjari, lakini kwa ujumla vinahifadhi aina sawa za data.

Hapa kuna muhtasari wa vifaa vya kivinjari vya kawaida:

* **Historia ya Urambazaji**: Inaandika ziara za mtumiaji kwenye tovuti, muhimu kwa kutambua ziara kwenye tovuti zenye nia mbaya.
* **Data ya Kiotomatiki**: Mapendekezo kulingana na utafutaji wa mara kwa mara, kutoa ufahamu unapounganishwa na historia ya urambazaji.
* **Alamisho**: Tovuti yaaniwa na mtumiaji kwa ufikio wa haraka.
* **Vifaa vya Nyongeza na Ongeza**: Vifaa vya kivinjari au ongeza zilizowekwa na mtumiaji.
* **Cache**: Inahifadhi maudhui ya wavuti (k.m., picha, faili za JavaScript) kuboresha nyakati za kupakia wavuti, muhimu kwa uchambuzi wa kiforensiki.
* **Kuingia**: Anahifadhi maelezo ya kuingia.
* **Favicons**: Vielelezo vinavyohusishwa na tovuti, vinavyoonekana kwenye vichupo na alamisho, muhimu kwa habari zaidi kuhusu ziara za mtumiaji.
* **Vikao vya Kivinjari**: Data inayohusiana na vikao vya kivinjari vilivyofunguliwa.
* **Vipakuzi**: Rekodi za faili zilizopakuliwa kupitia kivinjari.
* **Data ya Fomu**: Maelezo yaliyoingizwa kwenye fomu za wavuti, yaliyohifadhiwa kwa mapendekezo ya kiotomatiki ya baadaye.
* **Vielelezo**: Picha za hakikisho za tovuti.
* **Custom Dictionary.txt**: Maneno yaliyoongezwa na mtumiaji kwenye kamusi ya kivinjari.

## Firefox

Firefox inaandaa data ya mtumiaji ndani ya maelezo, yaliyohifadhiwa katika maeneo maalum kulingana na mfumo wa uendeshaji:

* **Linux**: `~/.mozilla/firefox/`
* **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Faili ya `profiles.ini` orod  ndani ya maelezo haya inaorodhesha maelezo ya mtumiaji. Data ya kila maelezo inahifadhiwa katika folda iliyoitwa katika kipengele cha `Path` ndani ya `profiles.ini`, iliyoko katika folda hiyo hiyo kama `profiles.ini` yenyewe. Ikiwa folda ya maelezo imepotea, inaweza kuwa imefutwa.

Ndani ya kila folda ya maelezo, unaweza kupata faili muhimu kadhaa:

* **places.sqlite**: Inahifadhi historia, alamisho, na vipakuzi. Zana kama [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) kwenye Windows inaweza kupata data ya historia.
* Tumia matakwa maalum ya SQL kutoa habari ya historia na vipakuzi.
* **bookmarkbackups**: Ina backups ya alamisho.
* **formhistory.sqlite**: Inahifadhi data ya fomu za wavuti.
* **handlers.json**: Inasimamia wakala wa itifaki.
* **persdict.dat**: Maneno ya kamusi ya kawaida.
* **addons.json** na **extensions.sqlite**: Maelezo kuhusu vifaa vya nyongeza na ongeza vilivyowekwa.
* **cookies.sqlite**: Uhifadhi wa kuki, na [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) inapatikana kwa ukaguzi kwenye Windows.
* **cache2/entries** au **startupCache**: Data ya cache, inayopatikana kupitia zana kama [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html).
* **favicons.sqlite**: Inahifadhi favicons.
* **prefs.js**: Mipangilio na mapendeleo ya mtumiaji.
* **downloads.sqlite**: Hifadhidata ya vipakuzi vya zamani, sasa imejumuishwa ndani ya places.sqlite.
* **thumbnails**: Vielelezo vya tovuti.
* **logins.json**: Maelezo ya kuingia yaliyofichwa.
* **key4.db** au **key3.db**: Inahifadhi funguo za kuchakata habari nyeti.

Kwa kuongezea, kuangalia mipangilio ya kuzuia udukuzi wa kivinjari kunaweza kufanywa kwa kutafuta viingilio vya `browser.safebrowsing` katika `prefs.js`, ikionyesha ikiwa vipengele vya kivinjari salama vimeanzishwa au havijaanzishwa.

Kujaribu kufichua nenosiri kuu, unaweza kutumia [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
Kwa skripti ifuatayo na wito unaweza kufafanua faili ya nenosiri la kufanya nguvu ya:

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
## Google Chrome

Google Chrome hifadhi maelezo ya mtumiaji katika maeneo maalum kulingana na mfumo wa uendeshaji:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Katika mabano haya, data nyingi ya mtumiaji inaweza kupatikana katika folda za **Default/** au **ChromeDefaultData/**. Faili zifuatazo zina data muhimu:

- **History**: Ina URL, vipakuliwa, na maneno muhimu ya utafutaji. Kwenye Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) inaweza kutumika kusoma historia. Safu ya "Transition Type" ina maana mbalimbali, ikiwa ni pamoja na mtumiaji bonyeza viungo, URLs zilizotyped, maombi ya fomu, na upya wa kurasa.
- **Cookies**: Hifadhi vidakuzi. Kwa ukaguzi, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) inapatikana.
- **Cache**: Inashikilia data iliyohifadhiwa. Kwa ukaguzi, watumiaji wa Windows wanaweza kutumia [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html).
- **Bookmarks**: Alama za mtumiaji.
- **Web Data**: Ina historia ya fomu.
- **Favicons**: Hifadhi favicons za tovuti.
- **Login Data**: Inajumuisha vitambulisho vya kuingia kama majina ya mtumiaji na nywila.
- **Current Session**/**Current Tabs**: Data kuhusu kikao cha kutembelea tovuti na vichupo vilivyofunguliwa.
- **Last Session**/**Last Tabs**: Taarifa kuhusu tovuti zilizokuwa zinaendeshwa wakati wa kikao cha mwisho kabla ya Chrome kufungwa.
- **Extensions**: Mafaili kwa ajili ya nyongeza na vifaa vya kivinjari.
- **Thumbnails**: Hifadhi picha ndogo za tovuti.
- **Preferences**: Faili tajiri kwa maelezo, ikiwa ni pamoja na mipangilio ya programu-jalizi, nyongeza, pop-ups, taarifa, na zaidi.
- **Browser’s built-in anti anti-phishing**: Ili kuthibitisha kama kinga ya kuvizia na ulinzi wa programu hasidi umewezeshwa, endesha `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Tafuta `{"enabled: true,"}` kwenye matokeo.

## **Uokoaji wa Data ya SQLite DB**

Kama unavyoweza kuona katika sehemu zilizopita, Chrome na Firefox hutumia **SQLite** databases kuhifadhi data. Ni rahisi **kuokoa vipande vilivyofutwa kwa kutumia zana** [**sqlparse**](https://github.com/padfoot999/sqlparse) **au** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 inasimamia data yake na metadata katika maeneo mbalimbali, ikisaidia katika kutenganisha maelezo yaliyohifadhiwa na maelezo yanayohusiana kwa urahisi wa kupata na usimamizi.

### Uhifadhi wa Metadata

Metadata ya Internet Explorer inahifadhiwa katika `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (na VX ikiwa V01, V16, au V24). Pamoja na hii, faili ya `V01.log` inaweza kuonyesha tofauti za muda wa marekebisho na `WebcacheVX.data`, ikionyesha haja ya marekebisho kwa kutumia `esentutl /r V01 /d`. Metadata hii, iliyohifadhiwa katika database ya ESE, inaweza kuokolewa na kukaguliwa kwa kutumia zana kama photorec na [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), mtawalia. Ndani ya jedwali la **Containers**, mtu anaweza kutofautisha jedwali au kontena maalum ambapo kila sehemu ya data inahifadhiwa, ikiwa ni pamoja na maelezo ya cache kwa zana zingine za Microsoft kama vile Skype.

### Ukaguzi wa Cache

Zana ya [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) inaruhusu ukaguzi wa cache, ikihitaji eneo la folda ya uchimbaji wa data ya cache. Metadata ya cache inajumuisha jina la faili, saraka, idadi ya ufikivu, asili ya URL, na alama za muda zinazoonyesha wakati wa uundaji wa cache, ufikivu, marekebisho, na muda wa kumalizika.

### Usimamizi wa Vidakuzi

Vidakuzi vinaweza kuchunguzwa kwa kutumia [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), na metadata inajumuisha majina, URLs, idadi ya ufikivu, na maelezo mbalimbali yanayohusiana na muda. Vidakuzi vya kudumu vinahifadhiwa katika `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, na vidakuzi vya kikao viko katika kumbukumbu.

### Maelezo ya Vipakuliwa

Metadata ya vipakuliwa inapatikana kupitia [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), na kontena maalum zikishikilia data kama URL, aina ya faili, na eneo la kupakua. Faili za kimwili zinaweza kupatikana chini ya `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historia ya Kutembelea Tovuti

Ili kupitia historia ya kutembelea tovuti, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) inaweza kutumika, ikihitaji eneo la faili za historia iliyochimbuliwa na usanidi kwa Internet Explorer. Metadata hapa inajumuisha muda wa marekebisho na ufikivu, pamoja na idadi ya ufikivu. Faili za historia zinapatikana katika `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URLs Zilizotyped

URLs zilizotyped na nyakati zao za matumizi zinahifadhiwa katika usajili chini ya `NTUSER.DAT` kwenye `Software\Microsoft\InternetExplorer\TypedURLs` na `Software\Microsoft\InternetExplorer\TypedURLsTime`, ikifuatilia URLs 50 za mwisho zilizoingizwa na mtumiaji na nyakati zao za mwisho za kuingizwa.

## Microsoft Edge

Microsoft Edge inahifadhi data ya mtumiaji katika `%userprofile%\Appdata\Local\Packages`. Njia za aina mbalimbali za data ni:

- **Njia ya Wasifu**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Historia, Vidakuzi, na Vipakuliwa**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Mipangilio, Alama za Kumbukumbu, na Orodha ya Kusoma**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStoreTP
* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
