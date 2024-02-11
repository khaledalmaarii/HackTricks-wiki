# macOS Lancering/Omgewingsbeperkings & Vertrouenskas

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Basiese Inligting

Lanceringbeperkings in macOS is ingevoer om sekuriteit te verbeter deur **te reguleer hoe, deur wie en vanwaar 'n proses geïnisieer kan word**. Dit is in macOS Ventura begin en bied 'n raamwerk wat **elke stelselbinêre in afsonderlike beperkingskategorieë** kategoriseer, wat gedefinieer word binne die **vertrouenskas**, 'n lys wat stelselbinêre en hul onderskeie hashs bevat. Hierdie beperkings strek tot elke uitvoerbare binêre binne die stelsel en behels 'n stel **reëls** wat die vereistes vir **die lancering van 'n spesifieke binêre** bepaal. Die reëls sluit selfbeperkings in wat 'n binêre moet bevredig, ouerbeperkings wat deur sy ouerproses nagekom moet word, en verantwoordelike beperkings wat deur ander relevante entiteite nagekom moet word.

Die meganisme strek tot derdeparty-apps deur **Omgewingsbeperkings**, wat begin vanaf macOS Sonoma, en stel ontwikkelaars in staat om hul apps te beskerm deur 'n **reeks sleutels en waardes vir omgewingsbeperkings** te spesifiseer.

Jy definieer **lanceringsomgewing en biblioteekbeperkings** in beperkingswoordeboeke wat jy ofwel stoor in **`launchd`-eiendomslys-lêers**, of in **afsonderlike eiendomslys-lêers** wat jy gebruik in kodeondertekening.

Daar is 4 tipes beperkings:

* **Selfbeperkings**: Beperkings wat van toepassing is op die **lopende** binêre.
* **Ouerproses**: Beperkings wat van toepassing is op die **ouer van die proses** (byvoorbeeld **`launchd`** wat 'n XP-diens uitvoer)
* **Verantwoordelike beperkings**: Beperkings wat van toepassing is op die **proses wat die diens aanroep** in 'n XPC-kommunikasie
* **Biblioteeklaaibeperkings**: Gebruik biblioteeklaaibeperkings om selektief kode te beskryf wat gelaai kan word

Dus, wanneer 'n proses probeer om 'n ander proses te lanceer - deur `execve(_:_:_:)` of `posix_spawn(_:_:_:_:_:_:)` te roep - kontroleer die bedryfstelsel dat die **uitvoerbare** lêer voldoen aan sy **eie selfbeperking**. Dit kontroleer ook dat die **uitvoerbare lêer van die ouerproses** voldoen aan die uitvoerbare se **ouerbeperking**, en dat die **uitvoerbare lêer van die verantwoordelike proses** voldoen aan die uitvoerbare se verantwoordelike prosesbeperking. As enige van hierdie lanceringbeperkings nie bevredig word nie, voer die bedryfstelsel die program nie uit nie.

As enige deel van die **biblioteekbeperking nie waar is nie** wanneer 'n biblioteek gelaai word, laai jou proses die biblioteek nie.

## LC Kategorieë

'n LC bestaan uit **feite** en **logiese bewerkings** (en, of...) wat feite kombineer.

Die [**feite wat 'n LC kan gebruik, is gedokumenteer**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Byvoorbeeld:

* is-init-proc: 'n Boole-waarde wat aandui of die uitvoerbare die bedryfstelsel se inisialisasieproses (`launchd`) moet wees.
* is-sip-protected: 'n Boole-waarde wat aandui of die uitvoerbare 'n lêer moet wees wat deur Stelselintegriteitsbeskerming (SIP) beskerm word.
* `on-authorized-authapfs-volume:` 'n Boole-waarde wat aandui of die bedryfstelsel die uitvoerbare vanaf 'n gemagtigde, geauthentiseerde APFS-volume gelaai het.
* `on-authorized-authapfs-volume`: 'n Boole-waarde wat aandui of die bedryfstelsel die uitvoerbare vanaf 'n gemagtigde, geauthentiseerde APFS-volume gelaai het.
* Cryptexes-volume
* `on-system-volume:` 'n Boole-waarde wat aandui of die bedryfstelsel die uitvoerbare vanaf die tans geboote stelselvolume gelaai het.
* Binne /System...
* ...

Wanneer 'n Apple-binêre lêer onderteken word, **ken dit dit toe aan 'n LC-kategorie** binne die **vertrouenskas**.

* **iOS 16 LC-kategorieë** is [**omgekeer en gedokumenteer hier**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* Huidige **LC-kategorieë (macOS 14** - Somona) is omgekeer en hul [**beskrywings kan hier gevind word**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Byvoorbeeld Kategorie 1 is:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: Moet in die Stelsel- of Cryptexes-volume wees.
* `launch-type == 1`: Moet 'n stelseldiens wees (plist in LaunchDaemons).
* `validation-category == 1`: 'n Bedryfstelsel-uitvoerbare lêer.
* `is-init-proc`: Launchd

### Omgekeerde LC-kategorieë

Jy het meer inligting [**hieroor hier**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), maar basies word hulle gedefinieer in **AMFI (AppleMobileFileIntegrity)**, so jy moet die Kernel Development Kit aflaai om die **KEXT** te kry. Die simbole wat begin met **`kConstraintCategory`** is die **interessante** een. Deur hulle te onttrek, sal jy 'n DER (ASN.1) gekodeerde stroom kry wat jy sal moet ontkodeer met [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) of die python-asn1-biblioteek en sy `dump.py` skrip, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) wat jou 'n meer verstaanbare string sal gee.

## Omgewingsbeperkings

Dit is die ingestelde Lanceerbeperkings wat gekonfigureer is in **derdepartytoepassings**. Die ontwikkelaar kan die **feite** en **logiese operandi** kies om die toegang tot die toepassing te beperk.

Dit is moontlik om die Omgewingsbeperkings van 'n toepassing op te som met:
```bash
codesign -d -vvvv app.app
```
## Vertrouenskas

In **macOS** is daar 'n paar vertrouenskassies:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

En in iOS lyk dit asof dit in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** is.

{% hint style="warning" %}
Op macOS wat op Apple Silicon-toestelle loop, sal AMFI weier om 'n Apple-ondertekende binêre lêer te laai as dit nie in die vertrouenskas is nie.
{% endhint %}

### Enumerating Trust Caches

Die vorige vertrouenskas-lêers is in die **IMG4** en **IM4P** formaat, waar IM4P die payload-seksie van 'n IMG4-formaat is.

Jy kan [**pyimg4**](https://github.com/m1stadev/PyIMG4) gebruik om die payload van databasisse te onttrek:

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

('n Ander opsie kan wees om die instrument [**img4tool**](https://github.com/tihmstar/img4tool) te gebruik, wat selfs in M1 sal loop, selfs as die vrystelling oud is en vir x86\_64 as jy dit in die regte plekke installeer).

Nou kan jy die instrument [**trustcache**](https://github.com/CRKatri/trustcache) gebruik om die inligting in 'n leesbare formaat te kry:
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
Die vertrouenskas volg die volgende struktuur, so die **LC-kategorie is die 4de kolom**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Dan kan jy 'n skrip soos [**hierdie een**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) gebruik om data te onttrek.

Vanuit daardie data kan jy die programme met 'n **lanceringsbeperkingswaarde van `0`** nagaan, wat diegene is wat nie beperk word nie ([**kyk hier**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) vir wat elke waarde beteken).

## Aanvalsvermindering

Lanceringsbeperkings sou verskeie ou aanvalle verminder deur **te verseker dat die proses nie in onverwagte toestande uitgevoer word nie:** Byvoorbeeld vanuit onverwagte plekke of deur 'n onverwagte ouerproses aangeroep te word (as slegs launchd dit moet lanceer)

Verder verminder Lanceringsbeperkings ook **afwaartse aanvalle**.

Dit verminder egter nie algemene XPC-misbruik, **Electron** kode-inspuitings of **dylib-inspuitings** sonder biblioteekvalidering (tensy die span-ID's wat biblioteke kan laai, bekend is).

### XPC Daemon-beskerming

In die Sonoma vrystelling is 'n noemenswaardige punt die **verantwoordelikheidskonfigurasie** van die daemon XPC-diens. Die XPC-diens is self verantwoordelik, in teenstelling met die verbindende kliënt wat verantwoordelik is. Dit word gedokumenteer in die terugvoer verslag FB13206884. Hierdie opstelling mag gebrekkig lyk, omdat dit sekere interaksies met die XPC-diens toelaat:

- **Lancerings van die XPC-diens**: As dit as 'n fout beskou word, laat hierdie opstelling nie toe dat die XPC-diens deur aanvallerkode geïnisieer word nie.
- **Verbinding met 'n aktiewe diens**: As die XPC-diens reeds loop (moontlik geaktiveer deur sy oorspronklike toepassing), is daar geen hindernisse om daarmee te verbind nie.

Hoewel dit voordelig kan wees om beperkings op die XPC-diens te implementeer deur **die venster vir potensiële aanvalle te versmal**, spreek dit nie die primêre bekommernis aan nie. Om die veiligheid van die XPC-diens te verseker, moet die verbindende kliënt doeltreffend **gevalideer word**. Dit bly die enigste metode om die diens se veiligheid te versterk. Dit is ook die moeite werd om op te let dat die genoemde verantwoordelikheidskonfigurasie tans operasioneel is, wat nie noodwendig ooreenstem met die bedoelde ontwerp nie.


### Electron-beskerming

Selfs al is dit nodig dat die toepassing deur LaunchService **geopen moet word** (in die ouers se beperkings). Dit kan bereik word deur **`open`** te gebruik (wat omgewingsveranderlikes kan instel) of deur die **Launch Services API** te gebruik (waar omgewingsveranderlikes aangedui kan word).

## Verwysings

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>
