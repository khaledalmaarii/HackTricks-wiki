# Vifaa vya Kivinjari

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mifumo ya kazi** kwa kutumia zana za **jamii yenye maendeleo zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Vifaa vya Kivinjari <a href="#id-3def" id="id-3def"></a>

Vifaa vya kivinjari ni pamoja na aina mbalimbali za data zilizohifadhiwa na vivinjari vya wavuti, kama historia ya urambazaji, alamisho, na data ya cache. Vifaa hivi vimehifadhiwa katika folda maalum ndani ya mfumo wa uendeshaji, tofauti katika eneo na jina kati ya vivinjari, lakini kwa ujumla vikihifadhi aina sawa za data.

Hapa kuna muhtasari wa vifaa vya kivinjari vya kawaida:

* **Historia ya Urambazaji**: Inachunguza ziara za mtumiaji kwenye tovuti, muhimu kwa kutambua ziara kwenye tovuti zenye nia mbaya.
* **Data ya Kujaza moja kwa moja**: Mapendekezo kulingana na utafutaji wa mara kwa mara, kutoa ufahamu unapounganishwa na historia ya urambazaji.
* **Alamisho**: Tovuti zilizohifadhiwa na mtumiaji kwa ufikio wa haraka.
* **Vifaa vya nyongeza na Ongeza-ons**: Vifaa vya nyongeza au ongeza-ons vilivyowekwa na mtumiaji.
* **Cache**: Inahifadhi maudhui ya wavuti (k.m., picha, faili za JavaScript) kuboresha nyakati za kupakia wavuti, muhimu kwa uchambuzi wa kiforensiki.
* **Kuingia**: Anuwai ya vibali vya kuingia.
* **Favicons**: Picha za alama zinazohusishwa na tovuti, zinazoonekana kwenye vichupo na alamisho, muhimu kwa habari zaidi kuhusu ziara za mtumiaji.
* **Vikao vya Kivinjari**: Data inayohusiana na vikao vya kivinjari vilivyofunguliwa.
* **Vipakuzi**: Rekodi za faili zilizopakuliwa kupitia kivinjari.
* **Data ya Fomu**: Taarifa zilizoingizwa kwenye fomu za wavuti, zilizohifadhiwa kwa mapendekezo ya kujaza moja kwa moja baadaye.
* **Vielelezo**: Picha za hakikisho za tovuti.
* **Custom Dictionary.txt**: Maneno yaliyoongezwa na mtumiaji kwenye kamusi ya kivinjari.

## Firefox

Firefox inaandaa data ya mtumiaji ndani ya maelezo, yaliyohifadhiwa katika maeneo maalum kulingana na mfumo wa uendeshaji:

* **Linux**: `~/.mozilla/firefox/`
* **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Faili ya `profiles.ini` ndani ya miongozo hii inaorodhesha maelezo ya mtumiaji. Data ya kila maelezo imehifadhiwa katika folda iliyoitwa katika kipengele cha `Path` ndani ya `profiles.ini`, iliyoko katika miongozo hiyo hiyo kama `profiles.ini` yenyewe. Ikiwa folda ya maelezo inakosekana, inaweza kuwa imefutwa.

Ndani ya kila folda ya maelezo, unaweza kupata faili muhimu kadhaa:

* **places.sqlite**: Inahifadhi historia, alamisho, na vipakuzi. Zana kama [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) kwenye Windows inaweza kupata data ya historia.
* Tumia matakwa maalum ya SQL kutoa habari ya historia na vipakuzi.
* **bookmarkbackups**: Ina nakala rudufu za alamisho.
* **formhistory.sqlite**: Inahifadhi data ya fomu za wavuti.
* **handlers.json**: Inasimamia wakala wa itifaki.
* **persdict.dat**: Maneno ya kamusi ya kawaida.
* **addons.json** na **extensions.sqlite**: Taarifa kuhusu vifaa vya nyongeza na ongeza-ons vilivyowekwa.
* **cookies.sqlite**: Uhifadhi wa kuki, na [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) inapatikana kwa ukaguzi kwenye Windows.
* **cache2/entries** au **startupCache**: Data ya cache, inayopatikana kupitia zana kama [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html).
* **favicons.sqlite**: Inahifadhi favicons.
* **prefs.js**: Mipangilio na mapendeleo ya mtumiaji.
* **downloads.sqlite**: Hifadhidata ya vipakuzi vya zamani, sasa imejumuishwa ndani ya places.sqlite.
* **thumbnails**: Vielelezo vya tovuti.
* **logins.json**: Taarifa za kuingia zilizo na siri.
* **key4.db** au **key3.db**: Inahifadhi funguo za kuchakata habari nyeti.

Kwa kuongezea, kuangalia mipangilio ya kuzuia udukuzi wa kivinjari kunaweza kufanywa kwa kutafuta muingilio wa `browser.safebrowsing` katika `prefs.js`, ikionyesha ikiwa vipengele vya kivinjari salama vimeanzishwa au havijaanzishwa.

Kujaribu kufichua nenosiri kuu, unaweza kutumia [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
Kwa skripti ifuatayo na wito unaweza kufafanua faili ya nenosiri la msingi:
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

- **History**: Ina URL, vipakuliwa, na maneno muhimu ya utafutaji. Kwenye Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) inaweza kutumika kusoma historia. Safu ya "Transition Type" ina maana mbalimbali, ikiwa ni pamoja na bonyeza za mtumiaji kwenye viungo, URL zilizotyped, maombi ya fomu, na upyaishaji wa ukurasa.
- **Cookies**: Hifadhi vidakuzi. Kwa ukaguzi, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) inapatikana.
- **Cache**: Inashikilia data iliyohifadhiwa. Kwa ukaguzi, watumiaji wa Windows wanaweza kutumia [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html).
- **Bookmarks**: Alama za mtumiaji.
- **Web Data**: Ina historia ya fomu.
- **Favicons**: Hifadhi alama za tovuti.
- **Login Data**: Inajumuisha vitambulisho vya kuingia kama majina ya mtumiaji na nywila.
- **Current Session**/**Current Tabs**: Data kuhusu kikao cha kuvinjari cha sasa na vichupo vilivyofunguliwa.
- **Last Session**/**Last Tabs**: Taarifa kuhusu tovuti zilizokuwa zinaendeshwa wakati wa kikao cha mwisho kabla ya Chrome kufungwa.
- **Extensions**: Mafaili kwa ajili ya nyongeza na vifaa vya kivinjari.
- **Thumbnails**: Hifadhi picha ndogo za tovuti.
- **Preferences**: Faili tajiri kwa maelezo, ikiwa ni pamoja na mipangilio kwa ajili ya programu-jalizi, nyongeza, pop-ups, taarifa, na zaidi.
- **Kuzuia zisizo za kivinjari**: Ili kuthibitisha kama kuzuia zisizo za kivinjari na ulinzi dhidi ya programu hasidi umewezeshwa, endesha `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Tafuta `{"enabled: true,"}` kwenye matokeo.

## **Uokoaji wa Data ya SQLite DB**

Kama unavyoweza kuona katika sehemu zilizopita, Chrome na Firefox hutumia **SQLite** databases kuhifadhi data. Ni rahisi **kuokoa vipande vilivyofutwa kwa kutumia zana** [**sqlparse**](https://github.com/padfoot999/sqlparse) **au** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 inahifadhi data yake na metadata katika maeneo mbalimbali, ikisaidia katika kutenganisha maelezo yaliyohifadhiwa na maelezo yanayohusiana kwa urahisi wa kupata na usimamizi.

### Uhifadhi wa Metadata

Metadata ya Internet Explorer inahifadhiwa katika `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (na VX ikiwa V01, V16, au V24). Pamoja na hii, faili ya `V01.log` inaweza kuonyesha tofauti za muda wa marekebisho na `WebcacheVX.data`, ikionyesha haja ya marekebisho kwa kutumia `esentutl /r V01 /d`. Metadata hii, iliyohifadhiwa katika database ya ESE, inaweza kuokolewa na kukaguliwa kwa kutumia zana kama photorec na [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), mtawalia. Ndani ya jedwali la **Containers**, mtu anaweza kutofautisha jedwali au kontena maalum ambapo kila sehemu ya data inahifadhiwa, ikiwa ni pamoja na maelezo ya cache kwa zana zingine za Microsoft kama vile Skype.

### Ukaguzi wa Cache

Zana ya [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) inaruhusu ukaguzi wa cache, ikihitaji eneo la folda ya uchimbaji wa data ya cache. Metadata ya cache inajumuisha jina la faili, saraka, idadi ya ufikivu, asili ya URL, na alama za muda zinazoonyesha wakati wa uundaji wa cache, ufikivu, marekebisho, na muda wa kumalizika.

### Usimamizi wa Vidakuzi

Vidakuzi vinaweza kuchunguzwa kwa kutumia [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), na metadata inajumuisha majina, URL, idadi ya ufikivu, na maelezo mbalimbali yanayohusiana na muda. Vidakuzi endelevu hifadhiwa katika `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, na vidakuzi vya kikao vinaishi kwenye kumbukumbu.

### Maelezo ya Vipakuliwa

Metadata ya vipakuliwa inapatikana kupitia [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), na kontena maalum zikishikilia data kama URL, aina ya faili, na eneo la kupakua. Faili za kimwili zinaweza kupatikana chini ya `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historia ya Uvinjari

Kwa kupitia historia ya uvinjari, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) inaweza kutumika, ikihitaji eneo la faili za historia iliyochimbuliwa na usanidi kwa Internet Explorer. Metadata hapa inajumuisha muda wa marekebisho na ufikivu, pamoja na idadi ya ufikivu. Faili za historia zinapatikana katika `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL Zilizotyped

URL zilizotyped na nyakati za matumizi yake zinahifadhiwa ndani ya usajili chini ya `NTUSER.DAT` kwenye `Software\Microsoft\InternetExplorer\TypedURLs` na `Software\Microsoft\InternetExplorer\TypedURLsTime`, ikifuatilia URL 50 za mwisho zilizoingizwa na mtumiaji na nyakati zao za mwisho za kuingizwa.

## Microsoft Edge

Microsoft Edge inahifadhi data ya mtumiaji katika `%userprofile%\Appdata\Local\Packages`. Njia za aina mbalimbali za data ni:

- **Njia ya Wasifu**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Historia, Vidakuzi, na Vipakuliwa**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Mipangilio, Alama za Kumbukumbu, na Orodha ya Kusoma**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Vikao Vilivyokuwa Vinaendeshwa Mwisho**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Data ya Safari inahifadhiwa katika `/Users/$User/Library/Safari`. Faili muhimu ni pamoja na:

- **History.db**: Ina `history_visits` na `history_items` jedwali na URL na muda wa ziara. Tumia `sqlite3` kuuliza.
- **Downloads.plist**: Maelezo kuhusu faili zilizopakuliwa.
- **Bookmarks.plist**: Hifadhi URL zilizopangwa.
- **TopSites.plist**: Tovuti zilizotembelewa mara nyingi.
- **Extensions.plist**: Orodha ya nyongeza za kivinjari cha Safari. Tumia `plutil` au `pluginkit` kuipata.
- **UserNotificationPermissions.plist**: Domain zilizoruhusiwa kutuma taarifa. Tumia `plutil` kuichambua.
- **LastSession.plist**: Vichupo kutoka kikao cha mwisho. Tumia `plutil` kuichambua.
- **Kuzuia zisizo za kivinjari**: Angalia kwa kutumia `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Majibu ya 1 inaonyesha kipengele kinafanya kazi.

## Opera

Data ya Opera iko katika `/Users/$USER/Library/Application Support/com.operasoftware.Opera` na inashiriki muundo wa historia na vipakuliwa wa Chrome.

- **Kuzuia zisizo za kivinjari**: Thibitisha kwa kuangalia kama `fraud_protection_enabled` katika faili ya Mapendeleo imeelekezwa kwa `true` kwa kutumia `grep`.

Njia hizi na amri ni muhimu kwa kupata na kuelewa data ya uvinjari iliyohifadhiwa na vivinjari tofauti vya wavuti.

## Marejeo

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
- **Kitabu: OS X Incident Response: Scripting and Analysis By Jaron Bradley ukurasa 123**

<figure><img src="../../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia taratibu za kiotomatiki** zinazotumia zana za jamii za juu zaidi duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:
* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
