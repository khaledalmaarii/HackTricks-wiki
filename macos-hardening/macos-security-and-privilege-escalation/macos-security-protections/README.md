# Ulinzi wa macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Gatekeeper

Gatekeeper kawaida hutumiwa kurejelea **Quarantine + Gatekeeper + XProtect**, moduli 3 za usalama za macOS ambazo zitajaribu **kuzuia watumiaji kutoka kwa kutekeleza programu inayoweza kuwa na nia mbaya iliyopakuliwa**.

Maelezo zaidi katika:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Mipaka ya Mchakato

### SIP - Ulinzi wa Uadilifu wa Mfumo

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sanduku la Mchanga

Sandbox ya MacOS **inapunguza matumizi** yanayoendesha ndani ya sanduku la mchanga kwa **vitendo vilivyoidhinishwa vilivyoelezwa katika wasifu wa Sanduku la Mchanga** programu inayoendesha nayo. Hii husaidia kuhakikisha kwamba **programu itakuwa ikifikia rasilimali zinazotarajiwa tu**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Uwazi, Ridhaa, na Udhibiti**

**TCC (Uwazi, Ridhaa, na Udhibiti)** ni mfumo wa usalama. Imeundwa kusimamia **ruhusa** za programu, hasa kwa kudhibiti ufikiaji wao kwa vipengele nyeti. Hii ni pamoja na mambo kama **huduma za eneo, mawasiliano, picha, kipaza sauti, kamera, upatikanaji, na ufikiaji kamili wa diski**. TCC inahakikisha kuwa programu zinaweza kufikia vipengele hivi baada ya kupata ridhaa wazi kutoka kwa mtumiaji, hivyo kuimarisha faragha na udhibiti wa data ya kibinafsi.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Vizuizi vya Kuzindua/Mazingira & Hifadhi ya Uaminifu

Vizuizi vya kuzindua katika macOS ni kipengele cha usalama cha **kudhibiti kuanzishwa kwa mchakato** kwa kufafanua **nani anaweza kuzindua** mchakato, **jinsi gani**, na **kutoka wapi**. Ilianzishwa katika macOS Ventura, inagawanya programu za mfumo katika vikundi vya vizuizi ndani ya **hifadhi ya uaminifu**. Kila faili ya kutekelezwa ina seti ya **kanuni** kwa ajili ya **uzinduzi wake**, ikiwa ni pamoja na vizuizi vya **ndani**, **wazazi**, na **wajibu**. Iliyopanuliwa kwa programu za watu wa tatu kama Vizuizi vya **Mazingira** katika macOS Sonoma, vipengele hivi husaidia kupunguza uwezekano wa udanganyifu wa mfumo kwa kudhibiti hali za kuzindua mchakato.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Zana ya Kuondoa Programu Hasidi

Zana ya Kuondoa Programu Hasidi (MRT) ni sehemu nyingine ya miundombinu ya usalama ya macOS. Kama jina linavyopendekeza, kazi kuu ya MRT ni **kuondoa programu hasidi inayojulikana kutoka kwenye mifumo iliyoambukizwa**.

Baada ya programu hasidi kugunduliwa kwenye Mac (kwa kutumia XProtect au njia nyingine), MRT inaweza kutumika kwa **kuondoa programu hasidi** kiotomatiki. MRT inafanya kazi kimya kimya nyuma ya pazia na kawaida inaendeshwa wakati mfumo unapofanyiwa sasisho au wakati ufafanuzi mpya wa programu hasidi unapakuliwa (inavyoonekana sheria ambazo MRT ina kugundua programu hasidi zipo ndani ya faili ya kutekelezwa).

Wakati XProtect na MRT zote ni sehemu ya hatua za usalama za macOS, zinafanya kazi tofauti:

* **XProtect** ni zana ya kuzuia. **Inachunguza faili wanapopakuliwa** (kupitia programu fulani), na ikiwa inagundua aina yoyote ya programu hasidi inayojulikana, **inazuia faili kufunguliwa**, hivyo kuzuia programu hasidi kuambukiza mfumo wako kwanza.
* **MRT**, kwa upande mwingine, ni **zana ya kurekebisha**. Inafanya kazi baada ya programu hasidi kugunduliwa kwenye mfumo, na lengo la kuondoa programu hasidi ili kusafisha mfumo.

Programu ya MRT iko katika **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Usimamizi wa Kazi za Nyuma

**macOS** sasa **inatoa tahadhari** kila wakati zana inatumia **njia inayojulikana kuendelea na utekelezaji wa nambari** (kama Vipengele vya Kuingia, Daemons...), ili mtumiaji ajue vizuri **programu gani inaendelea**.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

Hii inafanya kazi na **daemon** iliyoko katika `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` na **agent** katika `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Njia **`backgroundtaskmanagementd`** inajua kitu kimefungwa katika saraka ya kudumu ni kwa **kupata FSEvents** na kuunda **wahusika** kwa hizo.

Zaidi ya hayo, kuna faili ya plist ambayo ina **programu maarufu** inayodumu mara kwa mara inayosimamiwa na apple iliyoko: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

Inawezekana **kuchambua** vitu vyote vilivyowekwa kwenye historia ya nyuma kwa kutumia zana ya Apple cli:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Zaidi ya hayo, pia niwezekano wa kuorodhesha habari hii na [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Habari hii inahifadhiwa katika **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** na Terminal inahitaji FDA.

### Kuchezea na BTM

Wakati upyaji mpya unapatikana, tukio la aina ya **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** hutokea. Kwa hivyo, njia yoyote ya **kuzuia** tukio hili kutumwa au **mawakala kutoa tahadhari** kwa mtumiaji itasaidia mshambuliaji kuvuka BTM.

* **Kurejesha database**: Kukimbia amri ifuatayo kutarejesha database (inapaswa kuijenga upya kutoka mwanzo), hata hivyo, kwa sababu fulani, baada ya kukimbia hii, **hakuna upyaji mpya utakaoonywa hadi mfumo unapoanza tena**.
* **root** inahitajika.
```bash
# Reset the database
sfltool resettbtm
```
* **Acha Mawakala**: Inawezekana kutuma ishara ya kuacha kwa mawakala ili **isiwafahamishe mtumiaji** wakati ugunduzi mpya unapatikana.
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
* **Bug**: Ikiwa **mchakato uliounda uthabiti unakamilika haraka baada yake**, daemon itajaribu **kupata habari** kuhusu hilo, **kushindwa**, na **haitaweza kutuma tukio** linaloonyesha kuwa kitu kipya kinadumu.

Marejeo na **habari zaidi kuhusu BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
