# Kinga ya Usalama wa macOS

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Gatekeeper

Gatekeeper kawaida hutumiwa kumaanisha **Quarantine + Gatekeeper + XProtect**, moduli 3 za usalama za macOS ambazo zitajaribu **kuzuia watumiaji kutoka kutekeleza programu inayoweza kuwa mbaya iliyopakuliwa**.

Maelezo zaidi katika:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Vizuizi vya Mchakato

### SIP - Ulinzi wa Mfumo wa Integriti

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sanduku la Mchanga

Sanduku la MacOS **linapunguza maombi** yanayoendesha ndani ya sanduku la mchanga kwa **vitendo vilivyoidhinishwa katika wasifu wa Sanduku la mchanga** programu inayoendeshwa nayo. Hii husaidia kuhakikisha kwamba **programu itakuwa ikifikia rasilimali zilizotarajiwa tu**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Uwazi, Idhini, na Udhibiti**

**TCC (Uwazi, Idhini, na Udhibiti)** ni mfumo wa usalama. Imelenga **kusimamia ruhusa** za programu, hasa kwa kudhibiti upatikanaji wao kwa vipengele nyeti. Hii ni pamoja na mambo kama **huduma za eneo, mawasiliano, picha, kipaza sauti, kamera, upatikanaji wa uwezo, na upatikanaji kamili wa diski**. TCC inahakikisha kuwa programu zinaweza kupata vipengele hivi baada ya kupata idhini ya wazi kutoka kwa mtumiaji, hivyo kuimarisha faragha na udhibiti wa data ya kibinafsi.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Vizuizi vya Kuanzisha/Mazingira & Cache ya Kuaminika

Vizuizi vya kuanzisha katika macOS ni kipengele cha usalama cha **kusimamia kuanzisha kwa mchakato** kwa kufafanua **nani anaweza kuanzisha** mchakato, **vipi**, na **kutoka wapi**. Ilianzishwa katika macOS Ventura, wanachambua programu za msingi za mfumo katika **cache ya kuaminika**. Kila faili ya binari ina **mipangilio** iliyowekwa kwa **kuanzisha kwake**, ikiwa ni pamoja na vizuizi vya **kujitegemea**, **wazazi**, na **wajibu**. Kupanuliwa kwa programu za mtu wa tatu kama Vizuizi vya **Mazingira** katika macOS Sonoma, vipengele hivi husaidia kupunguza uwezekano wa kudanganywa kwa mfumo kwa kusimamia hali za kuanzisha mchakato.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Zana ya Kuondoa Programu hasidi

Zana ya Kuondoa Programu hasidi (MRT) ni sehemu nyingine ya miundombinu ya usalama ya macOS. Kama jina linavyopendekeza, kazi kuu ya MRT ni **kuondoa programu hasidi inayojulikana kutoka kwenye mifumo iliyoambukizwa**.

Maradhi ya programu hasidi yakiwa yamegunduliwa kwenye Mac (au na XProtect au kwa njia nyingine yoyote), MRT inaweza kutumika kiotomatiki **kuondoa programu hasidi**. MRT hufanya kazi kimya kimya nyuma ya pazia na kawaida hufanya kazi wakati mfumo unaposasishwa au wakati ufafanuzi mpya wa programu hasidi unapakuliwa (inaonekana sheria ambazo MRT ina kutambua programu hasidi zimo ndani ya faili ya binari).

Wakati XProtect na MRT zote ni sehemu ya hatua za usalama za macOS, zinafanya kazi tofauti:

* **XProtect** ni zana ya kuzuia. **Huchunguza faili wanapopakuliwa** (kupitia programu fulani), na ikiwa inagundua aina yoyote ya programu hasidi inayojulikana, **inazuia faili kufunguliwa**, hivyo kuzuia programu hasidi kuiambukiza mfumo wako kwanza.
* **MRT**, kwa upande mwingine, ni **zana ya kurekebisha**. Inafanya kazi baada ya programu hasidi kugunduliwa kwenye mfumo, lengo likiwa ni kuondoa programu hasidi ili kusafisha mfumo.

Programu ya MRT iko katika **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Usimamizi wa Kazi za Nyuma

**macOS** sasa **inatoa tahadhari** kila wakati zana inatumia **njia inayojulikana ya kudumisha utekelezaji wa nambari** (kama Vipengele vya Kuingia, Daemons...), hivyo mtumiaji anajua vizuri **ni programu gani inayodumisha**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Hii inaendeshwa na **daemon** iliyoko katika `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` na **agent** katika `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Njia **`backgroundtaskmanagementd`** inajua kitu kimefungwa katika folda ya kudumu ni kwa **kupata FSEvents** na kuunda **wahudumu** fulani kwa hilo.

Zaidi ya hayo, kuna faili ya plist inayohifadhi **programu zinazojulikana** ambazo mara nyingi hufanya kudumisha zinazosimamiwa na apple zilizoko: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Uchambuzi

Inawezekana **kuorodhesha** vipengele vyote vilivyowekwa vinavyotumia zana ya Apple cli:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Zaidi ya hayo, pia niwezekano wa kuorodhesha habari hii kwa [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Habari hii inahifadhiwa katika **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** na Terminal inahitaji FDA.

### Kuharibu BTM

Wakati uthabiti mpya unapopatikana tukio la aina **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Kwa hivyo, njia yoyote ya **kuzuia** tukio hili kutumwa au **mawakala kumuarifu** mtumiaji itasaidia mshambuliaji kuzidi BTM.

* **Kurejesha upya database**: Kukimbia amri ifuatayo kutarejesha upya database (inapaswa kuijenga upya kutoka mwanzoni), hata hivyo, kwa sababu fulani, baada ya kukimbia hii, **uthabiti mpya hautaarifiwa hadi mfumo uanzishwe tena**.
* **root** inahitajika.
```bash
# Reset the database
sfltool resettbtm
```
* **Acha Mawakala**: Inawezekana kutuma ishara ya kuacha kwa mawakala ili usiwe **unaweka mtumiaji alama** wakati uchunguzi mpya unapatikana.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Kosa**: Ikiwa **mchakato uliounda uthabiti upo haraka baada yake**, daemon atajaribu **kupata habari** kuhusu hilo, **kushindwa**, na **hautaweza kutuma tukio** linaloonyesha kitu kipya kinadumu.

Marejeo na **mambo zaidi kuhusu BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
