# Vizuizi vya Kuzindua/Mazingira ya macOS & Cache ya Imani

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Taarifa Msingi

Vizuizi vya kuzindua katika macOS vilianzishwa ili kuimarisha usalama kwa **kudhibiti jinsi, nani, na kutoka wapi mchakato unaweza kuanzishwa**. Ilianzishwa katika macOS Ventura, hutoa mfumo ambao unagawa **kila faili ya mfumo katika makundi tofauti ya vizuizi**, ambavyo vimefafanuliwa ndani ya **cache ya imani**, orodha inayojumuisha faili za mfumo na hash zao husika. Vizuizi hivi vinahusisha kila faili ya kutekelezwa ndani ya mfumo, na kuhusisha seti ya **kanuni** zinazoelezea mahitaji ya **kuzindua faili fulani**. Kanuni hizi zinajumuisha vizuizi vya ndani ambavyo faili ya kutekelezwa lazima itimize, vizuizi vya mzazi vinavyohitajika kutimizwa na mchakato wake mzazi, na vizuizi vya jukumu vinavyopaswa kuzingatiwa na vyombo vingine vinavyohusika.

Mfumo huu unahusisha programu za watu wa tatu kupitia **Vizuizi vya Mazingira**, kuanzia macOS Sonoma, kuruhusu watengenezaji kulinda programu zao kwa kutoa **seti ya funguo na thamani kwa vizuizi vya mazingira**.

Unafafanua **vizuizi vya kuzindua mazingira na maktaba** katika kamusi za vizuizi ambazo unahifadhi katika faili za **orodha ya mali ya `launchd`**, au katika **faili tofauti za orodha ya mali** ambazo unatumia katika kusaini kanuni.

Kuna aina 4 za vizuizi:

* **Vizuizi vya Ndani**: Vizuizi vinavyotumika kwa faili ya kutekelezwa **inayotumika**.
* **Mchakato wa Mzazi**: Vizuizi vinavyotumika kwa **mzazi wa mchakato** (kwa mfano **`launchd`** inayotekeleza huduma ya XP)
* **Vizuizi vya Jukumu**: Vizuizi vinavyotumika kwa **mchakato unaotumia huduma** katika mawasiliano ya XPC
* **Vizuizi vya Kupakia Maktaba**: Tumia vizuizi vya kupakia maktaba kuelezea sehemu za kanuni ambazo zinaweza kupakiwa

Kwa hivyo, wakati mchakato unajaribu kuzindua mchakato mwingine - kwa kuita `execve(_:_:_:)` au `posix_spawn(_:_:_:_:_:_:)` - mfumo wa uendeshaji unakagua kwamba **faili ya kutekelezwa** inatimiza **vizuizi vyake vya ndani**. Pia unakagua kwamba **faili ya kutekelezwa ya mchakato wa mzazi** inatimiza **vizuizi vya mzazi** vya faili ya kutekelezwa, na kwamba **faili ya kutekelezwa ya mchakato wa jukumu** inatimiza **vizuizi vya jukumu** vya faili ya kutekelezwa. Ikiwa vizuizi vyovyote vya kuzindua havikutimizwa, mfumo wa uendeshaji hautazindua programu.

Ikiwa wakati wa kupakia maktaba sehemu yoyote ya **vizuizi vya maktaba sio kweli**, mchakato wako **haupaki** maktaba.

## Jamii za LC

LC inajumuisha **ukweli** na **shughuli za mantiki** (na, au..) ambazo zinaunganisha ukweli.

[**Ukweli ambao LC inaweza kutumia umedokumentiwa**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Kwa mfano:

* is-init-proc: Thamani ya Boolean inayoonyesha ikiwa faili ya kutekelezwa lazima iwe mchakato wa kuanzisha wa mfumo wa uendeshaji (`launchd`).
* is-sip-protected: Thamani ya Boolean inayoonyesha ikiwa faili ya kutekelezwa lazima iwe faili iliyolindwa na Usalama wa Uadilifu wa Mfumo (SIP).
* `on-authorized-authapfs-volume:` Thamani ya Boolean inayoonyesha ikiwa mfumo wa uendeshaji umepakia faili ya kutekelezwa kutoka kwenye kizio cha APFS kilichoidhinishwa na kuthibitishwa.
* `on-authorized-authapfs-volume`: Thamani ya Boolean inayoonyesha ikiwa mfumo wa uendeshaji umepakia faili ya kutekelezwa kutoka kwenye kizio cha APFS kilichoidhinishwa na kuthibitishwa.
* Kizio cha Cryptexes
* `on-system-volume:` Thamani ya Boolean inayoonyesha ikiwa mfumo wa uendeshaji umepakia faili ya kutekelezwa kutoka kwenye kizio cha mfumo kinachotumiwa kwa sasa.
* Ndani ya /System...
* ...

Wakati faili ya Apple inaposainiwa, **inahusishwa na jamii ya LC** ndani ya **cache ya imani**.

* **Jamii za LC za iOS 16** zilikuwa [**zimegeuzwa na kudokumentiwa hapa**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* **Jamii za LC za sasa (macOS 14** - Somona) zimegeuzwa na [**maelezo yao yanaweza kupatikana hapa**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Kwa mfano, Jamii 1 ni:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: Lazima iwe kwenye kizio cha Mfumo au Cryptexes.
* `launch-type == 1`: Lazima iwe huduma ya mfumo (plist katika LaunchDaemons).
* `validation-category == 1`: Programu inayoweza kutekelezwa ya mfumo wa uendeshaji.
* `is-init-proc`: Launchd

### Kurejesha LC Jamii

Una habari zaidi [**kuihusu hapa**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), lakini kimsingi, zinatambuliwa katika **AMFI (AppleMobileFileIntegrity)**, kwa hivyo unahitaji kupakua Kituo cha Maendeleo cha Kernel ili kupata **KEXT**. Alama zinazoanza na **`kConstraintCategory`** ndizo zinazovutia. Kwa kuzitoa, utapata mkondo ulioandikwa kwa DER (ASN.1) ambao utahitaji kudekodeza na [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) au maktaba ya python-asn1 na skripti yake ya `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) ambayo itakupa herufi inayoeleweka zaidi.

## Vizuizi vya Mazingira

Hizi ni Vizuizi vya Mazingira vilivyowekwa katika **programu za watu wengine**. Mwandishi wa programu anaweza kuchagua **ukweli** na **masharti ya mantiki** ya kutumia katika programu yake ili kuzuia ufikiaji kwake.

Inawezekana kuorodhesha Vizuizi vya Mazingira ya programu na:
```bash
codesign -d -vvvv app.app
```
## Hifadhidata za Uaminifu

Katika **macOS** kuna hifadhidata chache za uaminifu:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

Na katika iOS inaonekana iko katika **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

{% hint style="warning" %}
Katika macOS inayotumia vifaa vya Apple Silicon, ikiwa faili iliyosainiwa na Apple haipo katika hifadhidata ya uaminifu, AMFI itakataa kuiweka.
{% endhint %}

### Kuhesabu Hifadhidata za Uaminifu

Faili za hifadhidata za uaminifu zilizotajwa hapo awali zina muundo wa **IMG4** na **IM4P**, huku IM4P ikiwa sehemu ya mzigo wa muundo wa IMG4.

Unaweza kutumia [**pyimg4**](https://github.com/m1stadev/PyIMG4) ili kuchambua mzigo wa hifadhidata:

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

(Chaguo lingine linaweza kuwa kutumia zana [**img4tool**](https://github.com/tihmstar/img4tool), ambayo itafanya kazi hata kwenye M1 hata kama toleo ni la zamani na kwa x86\_64 ikiwa utaifunga kwenye maeneo sahihi).

Sasa unaweza kutumia zana [**trustcache**](https://github.com/CRKatri/trustcache) ili kupata habari kwa muundo unaoweza kusomwa:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Hifadhidata ya imani inafuata muundo ufuatao, kwa hivyo **Jamii ya LC ni safu ya 4**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Kisha, unaweza kutumia script kama [**hii**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) ili kuchambua data.

Kutoka kwenye data hiyo, unaweza kuangalia Apps na **thamani ya vikwazo vya uzinduzi ya `0`**, ambazo ni zile ambazo hazina vikwazo ([**angalia hapa**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) kwa maelezo ya kila thamani).

## Kinga za Mashambulizi

Vikwazo vya Uzinduzi vingeweza kuzuia mashambulizi kadhaa ya zamani kwa **kufanya uhakika kwamba mchakato hautatekelezwa katika hali zisizotarajiwa:** Kwa mfano kutoka kwenye maeneo yasiyotarajiwa au kuitwa na mchakato wa mzazi usiotarajiwa (ikiwa ni launchd pekee inapaswa kuizindua)

Zaidi ya hayo, Vikwazo vya Uzinduzi pia **vinazuia mashambulizi ya kushusha kiwango.**

Hata hivyo, havizuizi matumizi mabaya ya XPC, uingizaji wa kanuni za Electron au uingizaji wa dylib bila uthibitisho wa maktaba (isipokuwa kitambulisho cha timu ambazo zinaweza kupakia maktaba kinajulikana).

### Kinga ya XPC Daemon

Katika toleo la Sonoma, jambo muhimu ni **mpangilio wa jukumu** la huduma ya XPC daemon. Huduma ya XPC inawajibika kwa ajili yake, tofauti na mteja anayehusika. Hii imeandikwa katika ripoti ya maoni FB13206884. Mpangilio huu unaweza kuonekana kuwa na kasoro, kwani inaruhusu mwingiliano fulani na huduma ya XPC:

- **Kuzindua Huduma ya XPC**: Ikiwa inachukuliwa kuwa ni kasoro, mpangilio huu haumruhusu kuanzisha huduma ya XPC kupitia kanuni ya mshambuliaji.
- **Kuunganisha kwenye Huduma Iliyopo**: Ikiwa huduma ya XPC tayari inaendeshwa (labda imeamilishwa na programu yake ya awali), hakuna vizuizi vya kuunganisha nayo.

Ingawa kuweka vikwazo kwenye huduma ya XPC kunaweza kuwa na manufaa kwa **kupunguza fursa za mashambulizi**, haitatua wasiwasi kuu. Kuhakikisha usalama wa huduma ya XPC kimsingi kunahitaji **uthibitisho wa mteja anayeunganisha kwa ufanisi**. Hii ndiyo njia pekee ya kuimarisha usalama wa huduma hiyo. Pia, ni muhimu kutambua kuwa mpangilio wa jukumu uliotajwa unatumika kwa sasa, ambao huenda usilingane na muundo uliokusudiwa.


### Kinga ya Electron

Hata kama inahitajika kwamba programu lazima **izinduliwe na LaunchService** (katika vikwazo vya wazazi). Hii inaweza kufanikishwa kwa kutumia **`open`** (ambayo inaweza kuweka mazingira ya mazingira) au kutumia **API ya Huduma za Uzinduzi** (ambapo mazingira ya mazingira yanaweza kuonyeshwa).

## Marejeo

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa katika HackTricks**? Au ungependa kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>
