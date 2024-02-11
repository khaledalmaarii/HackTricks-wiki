# Vifaa vya Kivinjari

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa katika HackTricks** au **kupakua HackTricks katika PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia kiotomatiki** mchakato wa kazi ulioendeshwa na zana za jamii za **juu zaidi duniani**.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Vifaa vya Kivinjari <a href="#id-3def" id="id-3def"></a>

Vifaa vya kivinjari ni pamoja na aina mbalimbali za data zilizohifadhiwa na vivinjari vya wavuti, kama historia ya urambazaji, alamisho, na data ya cache. Vifaa hivi vimehifadhiwa katika folda maalum ndani ya mfumo wa uendeshaji, tofauti katika eneo na jina kati ya vivinjari, lakini kwa ujumla vikihifadhi aina sawa za data.

Hapa kuna muhtasari wa vifaa vya kivinjari vya kawaida zaidi:

- **Historia ya Urambazaji**: Inafuatilia ziara za mtumiaji kwenye tovuti, inayofaa kwa kutambua ziara kwenye tovuti zenye nia mbaya.
- **Data ya Kujaza Kiotomatiki**: Mapendekezo kulingana na utafutaji mara kwa mara, inayotoa ufahamu wakati inachanganywa na historia ya urambazaji.
- **Alamisho**: Tovuti zilizohifadhiwa na mtumiaji kwa ufikiaji wa haraka.
- **Vifaa vya Ongeza na Nyongeza**: Vivinjari vya ongeza au nyongeza vilivyowekwa na mtumiaji.
- **Cache**: Inahifadhi yaliyomo ya wavuti (k.m., picha, faili za JavaScript) ili kuboresha wakati wa kupakia tovuti, muhimu kwa uchambuzi wa kisayansi.
- **Ingia**: Hifadhi ya vitambulisho vya kuingia.
- **Favicons**: Picha zinazohusiana na tovuti, zinazoonekana kwenye vichupo na alamisho, zinazofaa kwa habari zaidi kuhusu ziara za mtumiaji.
- **Vikao vya Kivinjari**: Data inayohusiana na vikao vya kivinjari vilivyofunguliwa.
- **Vipakuzi**: Rekodi za faili zilizopakuliwa kupitia kivinjari.
- **Data ya Fomu**: Taarifa zilizoingizwa kwenye fomu za wavuti, zilizohifadhiwa kwa mapendekezo ya kujaza kiotomatiki ya baadaye.
- **Picha za Onyesho**: Picha za hakikisho za tovuti.
- **Custom Dictionary.txt**: Maneno yaliyoongezwa na mtumiaji kwenye kamusi ya kivinjari.


## Firefox

Firefox inapanga data ya mtumiaji ndani ya profaili, iliyohifadhiwa katika maeneo maalum kulingana na mfumo wa uendeshaji:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Faili ya `profiles.ini` ndani ya saraka hizi inaorodhesha profaili za mtumiaji. Data ya kila profaili imehifadhiwa katika saraka iliyoitwa kwenye kipengele cha `Path` ndani ya `profiles.ini`, iliyoko katika saraka ile ile kama `profiles.ini` yenyewe. Ikiwa saraka ya profaili imepotea, inaweza kuwa imefutwa.

Ndani ya kila saraka ya profaili, unaweza kupata faili muhimu kadhaa:

- **places.sqlite**: Inahifadhi historia, alamisho, na vipakuzi. Zana kama [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kwenye Windows inaweza kupata data ya historia.
- Tumia maswali maalum ya SQL ili kuchambua historia na habari za vipakuzi.
- **bookmarkbackups**: Ina nakala rudufu za alamisho.
- **formhistory.sqlite**: Inahifadhi data ya fomu za wavuti.
- **handlers.json**: Inasimamia wakala wa itifaki.
- **persdict.dat**: Maneno ya kamusi ya desturi.
- **addons.json** na **extensions.sqlite**: Taarifa juu ya ongeza na nyongeza zilizowekwa.
- **cookies.sqlite**: Uhifadhi wa kuki, na [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) inapatikana kwa ukaguzi kwenye Windows.
- **cache2/entries** au **startupCache**: Data ya cache, inayopatikana kupitia zana kama [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Inahifadhi favicons.
- **prefs.js**: Mipangilio na mapendekezo ya mtumiaji.
- **downloads.sqlite**: Hifadhidata ya vipakuzi vya zamani, sasa imejumuishwa ndani ya places.sqlite.
- **thumbnails**: Picha za hakikisho za tovuti.
- **logins.json**: Taarifa za kuingia zilizofichwa.
- **key4.db** au **key3.db**: Inahifadhi funguo za kusimbua habari nyeti.

Kwa kuongezea, kuangalia mipangilio ya kuzuia udanganyifu ya kivinjari kunaweza kufanywa kwa kutafuta kuingia kwa `browser.safebrowsing` katika `prefs.js`, ikionyesha ikiwa vipengele vya kivinjari salama vimeamilishwa au kimezimwa.


Kujaribu kusimbua nenosiri kuu, unaweza kutumia [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
Kwa kutumia hati na wito ufuatao, unaweza kubainisha faili ya nenosiri ya kuvunja nguvu:

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

Google Chrome hifadhi maelezo ya watumiaji katika maeneo maalum kulingana na mfumo wa uendeshaji:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Katika mafaili haya, data nyingi ya mtumiaji inaweza kupatikana katika folda za **Default/** au **ChromeDefaultData/**. Faili zifuatazo zina data muhimu:

- **History**: Ina URL, kupakua, na maneno muhimu ya utafutaji. Katika Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) inaweza kutumika kusoma historia. Safu ya "Transition Type" ina maana mbalimbali, ikiwa ni pamoja na bonyeza za mtumiaji kwenye viungo, URL zilizotajwa, utumaji wa fomu, na upya wa ukurasa.
- **Cookies**: Hifadhi kuki. Kwa ukaguzi, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) inapatikana.
- **Cache**: Inashikilia data iliyohifadhiwa. Watumiaji wa Windows wanaweza kutumia [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) kufanya ukaguzi.
- **Bookmarks**: Alama za mtumiaji.
- **Web Data**: Ina historia ya fomu.
- **Favicons**: Hifadhi ikoni za wavuti.
- **Login Data**: Inajumuisha vitambulisho vya kuingia kama majina ya mtumiaji na nywila.
- **Current Session**/**Current Tabs**: Data kuhusu kikao cha sasa cha kuvinjari na vichupo vilivyofunguliwa.
- **Last Session**/**Last Tabs**: Taarifa kuhusu tovuti zilizokuwa hai wakati wa kikao cha mwisho kabla ya Chrome kufungwa.
- **Extensions**: Folders kwa ajili ya nyongeza na vifaa vya kivinjari.
- **Thumbnails**: Hifadhi picha ndogo za wavuti.
- **Preferences**: Faili yenye habari nyingi, ikiwa ni pamoja na mipangilio kwa ajili ya programu-jalizi, nyongeza, pop-ups, taarifa, na zaidi.
- **Browser’s built-in anti-phishing**: Ili kuthibitisha ikiwa kinga ya kuzuia ulaghai na programu hasidi imeamilishwa, endesha `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Tafuta `{"enabled: true,"}` katika matokeo.


## **Uokoaji wa Data ya SQLite DB**

Kama unavyoweza kubaini katika sehemu zilizotangulia, Chrome na Firefox hutumia **SQLite** databases kuhifadhi data. Ni rahisi **kurejesha vipengele vilivyofutwa kwa kutumia zana** [**sqlparse**](https://github.com/padfoot999/sqlparse) **au** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 inasimamia data yake na metadata katika maeneo mbalimbali, ikisaidia kutenganisha habari iliyohifadhiwa na maelezo yanayohusiana kwa urahisi wa kupata na usimamizi.

### Uhifadhi wa Metadata
Metadata ya Internet Explorer inahifadhiwa katika `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (na VX ikiwa ni V01, V16, au V24). Pamoja na hii, faili ya `V01.log` inaweza kuonyesha tofauti za muda wa kubadilisha na `WebcacheVX.data`, ikionyesha haja ya kurekebisha kwa kutumia `esentutl /r V01 /d`. Metadata hii, iliyohifadhiwa katika database ya ESE, inaweza kurejeshwa na kukaguliwa kwa kutumia zana kama photorec na [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), mtawalia. Ndani ya meza ya **Containers**, mtu anaweza kutambua meza au vyombo maalum ambapo kila sehemu ya data inahifadhiwa, ikiwa ni pamoja na maelezo ya cache kwa zana zingine za Microsoft kama vile Skype.

### Ukaguzi wa Cache
Zana ya [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) inaruhusu ukaguzi wa cache, ikihitaji eneo la folda ya uchimbaji wa data ya cache. Metadata ya cache inajumuisha jina la faili, saraka, idadi ya ufikiaji, asili ya URL, na alama za muda zinazoonyesha wakati wa kuunda cache, ufikiaji, mabadiliko, na muda wa kumalizika.

### Usimamizi wa Kuki
Kuki zinaweza kuchunguzwa kwa kutumia [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), na metadata inajumuisha majina, URL, idadi ya ufikiaji, na maelezo mbalimbali yanayohusiana na wakati. Kuki za kudumu zimehifadhiwa katika `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, na kuki za kikao zinapatikana kwenye kumbukumbu.

### Maelezo ya Upakuaji
Metadata ya upakuaji inapatikana kupitia [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), na vyombo maalum vikishikilia data kama vile URL, aina ya faili, na eneo la upakuaji. Faili halisi zinaweza kupatikana chini ya `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historia ya Kuvinjari
Ili kupitia historia ya kuvinjari, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) inaweza kutumika, ikihitaji eneo la faili za historia zilizochimbwa na usanidi kwa Internet Explorer. Metadata hapa inajumuisha muda wa kubadilisha na ufikiaji, pamoja na idadi ya ufikiaji. Faili za historia zinapatikana katika `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL Zilizotajwa
URL zilizotajwa na nyakati za matumizi yao zimehifadhiwa katika usajili chini ya `NTUSER.DAT` katika `Software\Microsoft\InternetExplorer\TypedURLs` na `Software\Microsoft\InternetExplorer\TypedURLsTime`, zikifuatilia URL 50 za mwisho zilizoingizwa na mtumiaji na nyakati za mwisho za kuingizwa.

## Microsoft Edge

Microsoft Edge hifadhi data ya mtumiaji katika `%userprofile%\Appdata\Local\Packages`. Njia za aina mbalimbali za data ni:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee.
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
