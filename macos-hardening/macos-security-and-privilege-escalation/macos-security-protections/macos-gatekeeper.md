# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Gatekeeper

**Gatekeeper** is 'n sekuriteitskenmerk wat ontwikkel is vir Mac-bedryfstelsels, ontwerp om te verseker dat gebruikers slegs **vertroude sagteware** op hul stelsels gebruik. Dit funksioneer deur die **validering** van sagteware wat 'n gebruiker aflaai en probeer oopmaak van **bronne buite die App Store**, soos 'n toepassing, 'n invoegtoepassing of 'n installeerpakket.

Die sleutel-meganisme van Gatekeeper lê in sy **verifikasieproses**. Dit kontroleer of die afgelaaide sagteware **deur 'n erkende ontwikkelaar onderteken** is, wat die egtheid van die sagteware verseker. Verder bepaal dit of die sagteware **deur Apple genotariseer** is, wat bevestig dat dit geen bekende skadelike inhoud bevat nie en nie na genotariseering gewysig is nie.

Daarbenewens versterk Gatekeeper gebruikersbeheer en -sekuriteit deur gebruikers te **vra om die oopmaak van afgelaaide sagteware goed te keur** vir die eerste keer. Hierdie beskerming help voorkom dat gebruikers per ongeluk potensieel skadelike uitvoerbare kode uitvoer wat hulle dalk vir 'n onskadelike databestand gehou het.

### Toepassinghandtekeninge

Toepassinghandtekeninge, ook bekend as kodehandtekeninge, is 'n kritieke komponent van Apple se sekuriteitsinfrastruktuur. Dit word gebruik om die identiteit van die sagteware-outeur (die ontwikkelaar) te **verifieer** en om te verseker dat die kode nie sedert die laaste ondertekening gewysig is nie.

So werk dit:

1. **Onderteken die Toepassing:** Wanneer 'n ontwikkelaar gereed is om hul toepassing te versprei, **onderteken hulle die toepassing met 'n privaat sleutel**. Hierdie privaat sleutel is gekoppel aan 'n **sertifikaat wat Apple aan die ontwikkelaar uitreik** wanneer hulle inskryf vir die Apple Developer Program. Die ondertekeningsproses behels die skep van 'n kriptografiese has van alle dele van die toepassing en die versleuteling van hierdie has met die ontwikkelaar se privaat sleutel.
2. **Versprei die Toepassing:** Die ondertekende toepassing word dan saam met die ontwikkelaar se sertifikaat, wat die ooreenstemmende openbare sleutel bevat, aan gebruikers versprei.
3. **Verifieer die Toepassing:** Wanneer 'n gebruiker die toepassing aflaai en probeer uitvoer, gebruik hul Mac-bedryfstelsel die openbare sleutel van die ontwikkelaar se sertifikaat om die has te ontsluit. Dit bereken dan die has opnuut op grond van die huidige toestand van die toepassing en vergelyk dit met die ontslote has. As hulle ooreenstem, beteken dit dat **die toepassing nie gewysig is** sedert die ontwikkelaar dit onderteken het nie, en die stelsel laat die toepassing toe om uitgevoer te word.

Toepassinghandtekeninge is 'n essensiële deel van Apple se Gatekeeper-tegnologie. Wanneer 'n gebruiker probeer om 'n toepassing wat van die internet afgelaai is, **oop te maak**, verifieer Gatekeeper die toepassinghandtekening. As dit onderteken is met 'n sertifikaat wat deur Apple aan 'n bekende ontwikkelaar uitgereik is en die kode nie gewysig is nie, laat Gatekeeper die toepassing toe om uitgevoer te word. Andersins blokkeer dit die toepassing en waarsku die gebruiker.

Vanaf macOS Catalina **kontroleer Gatekeeper ook of die toepassing genotariseer is** deur Apple, wat 'n ekstra laag sekuriteit toevoeg. Die genotariseeringsproses kontroleer die toepassing vir bekende sekuriteitsprobleme en skadelike kode, en as hierdie kontroles slaag, voeg Apple 'n kaartjie by die toepassing wat Gatekeeper kan verifieer.

#### Kontroleer Handtekeninge

Wanneer jy 'n **malwaremonster** kontroleer, moet jy altyd die handtekening van die binêre lêer **kontroleer**, aangesien die **ontwikkelaar** wat dit onderteken het, moontlik al **verwant** is aan **malware**.

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```

### Notarisering

Apple se notariseringproses dien as 'n addisionele beskerming om gebruikers te beskerm teen potensieel skadelike sagteware. Dit behels dat die **ontwikkelaar hul aansoek vir ondersoek indien** by **Apple se Notary-diens**, wat nie verwar moet word met App Review nie. Hierdie diens is 'n **geoutomatiseerde stelsel** wat die ingediende sagteware ondersoek vir die teenwoordigheid van **skadelike inhoud** en enige potensiële probleme met kode-ondertekening.

As die sagteware hierdie ondersoek **slaag sonder om enige bekommernisse te veroorsaak**, genereer die Notary-diens 'n notariseringstiket. Die ontwikkelaar moet dan hierdie tiket aan hul sagteware **heg**, 'n proses wat bekend staan as 'stapling'. Verder word die notariseringstiket ook aanlyn gepubliseer waar Gatekeeper, Apple se sekuriteitstegnologie, daarby kan kom.

By die gebruiker se eerste installasie of uitvoering van die sagteware, **informeer die teenwoordigheid van die notariseringstiket - hetsy aan die uitvoerbare lêer geheg of aanlyn gevind - Gatekeeper dat die sagteware deur Apple genotariseer is**. As gevolg hiervan vertoon Gatekeeper 'n beskrywende boodskap in die aanvanklike opstartvenster, wat aandui dat die sagteware deur Apple ondersoek is vir skadelike inhoud. Hierdie proses verbeter dus die gebruiker se vertroue in die veiligheid van die sagteware wat hulle op hul stelsels installeer of uitvoer.

### Enumerating GateKeeper

GateKeeper is **verskeie sekuriteitskomponente** wat voorkom dat onbetroubare programme uitgevoer word en is ook **een van die komponente**.

Dit is moontlik om die **status** van GateKeeper te sien met:

```bash
# Check the status
spctl --status
```

{% hint style="danger" %}
Let daarop dat GateKeeper-handtekeningkontroles slegs uitgevoer word op lêers met die Karantyn-eienskap, nie op elke lêer nie.
{% endhint %}

GateKeeper sal nagaan of 'n binêre lêer uitgevoer kan word volgens die voorkeure en handtekening:

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

Die databasis wat hierdie konfigurasie bevat, is geleë in **`/var/db/SystemPolicy`**. Jy kan hierdie databasis as 'n root-gebruiker nagaan met:

```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```

Let daarop hoe die eerste reël geëindig het in "**App Store**" en die tweede een in "**Developer ID**" en dat dit in die vorige afbeelding **ingeskakel was om programme van die App Store en geïdentifiseerde ontwikkelaars uit te voer**. As jy daardie instelling na App Store verander, sal die "**Notarized Developer ID" reëls verdwyn**.

Daar is ook duisende reëls van **tipe GKE**:

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

Hierdie is hasings wat afkomstig is van **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** en **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

Of jy kan die vorige inligting lys met:

```bash
sudo spctl --list
```

Die opsies **`--master-disable`** en **`--global-disable`** van **`spctl`** sal hierdie handtekeningkontroles heeltemal **deaktiveer**:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

Wanneer dit volledig geaktiveer is, sal 'n nuwe opsie verskyn:

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om **te kontroleer of 'n App deur GateKeeper toegelaat sal word** met:

```bash
spctl --assess -v /Applications/App.app
```

Dit is moontlik om nuwe reëls by GateKeeper toe te voeg om die uitvoering van sekere programme toe te staan met:

```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```

### Karantene-lêers

By die aflaai van 'n toepassing of lêer, heg spesifieke macOS-toepassings soos webblaaier of e-poskliënte 'n verlengde lêereienskap, algemeen bekend as die "karantenevlag", aan die afgelaaide lêer. Hierdie eienskap dien as 'n sekuriteitsmaatreël om die lêer te merk as afkomstig van 'n onbetroubare bron (die internet) en moontlik risiko's in te hou. Nie alle toepassings heg egter hierdie eienskap aan nie, byvoorbeeld gewone BitTorrent-kliënt sagteware omseil gewoonlik hierdie proses.

Die teenwoordigheid van 'n karantenevlag dui macOS se Gatekeeper-sekuriteitsfunksie aan wanneer 'n gebruiker probeer om die lêer uit te voer.

In die geval waar die karantenevlag nie teenwoordig is nie (soos met lêers wat via sommige BitTorrent-kliënte afgelaai is), mag Gatekeeper se kontroles nie uitgevoer word nie. Gebruikers moet dus versigtig wees wanneer hulle lêers van minder veilige of onbekende bronne oopmaak.

{% hint style="info" %}
Die **geldigheid** van kodesignature word **gekontroleer** deur 'n hulpbron-intensiewe proses wat die generering van kriptografiese hakies van die kode en al sy gebundelde hulpbronne insluit. Verder behels die kontrole van sertifikaatgeldigheid 'n aanlynkontrole na Apple se bedieners om te sien of dit herroep is nadat dit uitgereik is. Om hierdie redes is 'n volledige kodesignatuur- en notariseringkontrole **onprakties om elke keer as 'n toepassing uitgevoer word, uit te voer**.

Daarom word hierdie kontroles **slegs uitgevoer wanneer toepassings met die gekwarantyn-kenmerk uitgevoer word**.
{% endhint %}

{% hint style="warning" %}
Hierdie eienskap moet **deur die toepassing wat die lêer skep/aflaai** word.

Tog sal lêers wat gesandboks is, hierdie eienskap aan elke lêer wat hulle skep, heg. En nie-gesandbokste programme kan dit self instel, of die [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) sleutel in die **Info.plist** spesifiseer, wat die stelsel die `com.apple.quarantine` verlengde eienskap op die geskepte lêers sal stel.
{% endhint %}

Dit is moontlik om **die status te kontroleer en in/uit te skakel** (root vereis) met:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

Jy kan ook **vasstel of 'n lêer die karantyn verlengde eienskap het** met:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

Kyk na die **waarde** van die **uitgebreide** **eienskappe** en vind uit watter toepassing die karantyn-eienskap geskryf het met:

```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```

Eintlik kan 'n proses "kwarentynvlaggies aan die lêers wat dit skep, toewys" (ek het probeer om die USER\_APPROVED-vlag in 'n geskepte lêer toe te pas, maar dit sal nie toegepas word nie):

<details>

<summary>Bronkode pas kwarentynvlaggies toe</summary>

\`\`\`c #include #include

enum qtn\_flags { QTN\_FLAG\_DOWNLOAD = 0x0001, QTN\_FLAG\_SANDBOX = 0x0002, QTN\_FLAG\_HARD = 0x0004, QTN\_FLAG\_USER\_APPROVED = 0x0040, };

\#define qtn\_proc\_alloc \_qtn\_proc\_alloc #define qtn\_proc\_apply\_to\_self \_qtn\_proc\_apply\_to\_self #define qtn\_proc\_free \_qtn\_proc\_free #define qtn\_proc\_init \_qtn\_proc\_init #define qtn\_proc\_init\_with\_self \_qtn\_proc\_init\_with\_self #define qtn\_proc\_set\_flags \_qtn\_proc\_set\_flags #define qtn\_file\_alloc \_qtn\_file\_alloc #define qtn\_file\_init\_with\_path \_qtn\_file\_init\_with\_path #define qtn\_file\_free \_qtn\_file\_free #define qtn\_file\_apply\_to\_path \_qtn\_file\_apply\_to\_path #define qtn\_file\_set\_flags \_qtn\_file\_set\_flags #define qtn\_file\_get\_flags \_qtn\_file\_get\_flags #define qtn\_proc\_set\_identifier \_qtn\_proc\_set\_identifier

typedef struct \_qtn\_proc \*qtn\_proc\_t; typedef struct \_qtn\_file \*qtn\_file\_t;

int qtn\_proc\_apply\_to\_self(qtn\_proc\_t); void qtn\_proc\_init(qtn\_proc\_t); int qtn\_proc\_init\_with\_self(qtn\_proc\_t); int qtn\_proc\_set\_flags(qtn\_proc\_t, uint32\_t flags); qtn\_proc\_t qtn\_proc\_alloc(); void qtn\_proc\_free(qtn\_proc\_t); qtn\_file\_t qtn\_file\_alloc(void); void qtn\_file\_free(qtn\_file\_t qf); int qtn\_file\_set\_flags(qtn\_file\_t qf, uint32\_t flags); uint32\_t qtn\_file\_get\_flags(qtn\_file\_t qf); int qtn\_file\_apply\_to\_path(qtn\_file\_t qf, const char \*path); int qtn\_file\_init\_with\_path(qtn\_file\_t qf, const char _path); int qtn\_proc\_set\_identifier(qtn\_proc\_t qp, const char_ bundleid);

int main() {

qtn\_proc\_t qp = qtn\_proc\_alloc(); qtn\_proc\_set\_identifier(qp, "xyz.hacktricks.qa"); qtn\_proc\_set\_flags(qp, QTN\_FLAG\_DOWNLOAD | QTN\_FLAG\_USER\_APPROVED); qtn\_proc\_apply\_to\_self(qp); qtn\_proc\_free(qp);

FILE \*fp; fp = fopen("thisisquarantined.txt", "w+"); fprintf(fp, "Hello Quarantine\n"); fclose(fp);

return 0;

}

````
</details>

En **verwyder** daardie eienskap met:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
````

En vind al die gekwarantyniseerde lêers met:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Kwarantyninligting word ook gestoor in 'n sentrale databasis wat deur LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** bestuur word.

**Quarantine.kext**

Die kernel-uitbreiding is slegs beskikbaar deur die **kernel-cache op die stelsel**; jy _kan_ egter die **Kernel Debug Kit aflaai vanaf https://developer.apple.com/**, wat 'n gesimboliseerde weergawe van die uitbreiding sal bevat.

#### XProtect

XProtect is 'n ingeboude **anti-malware**-funksie in macOS. XProtect **kontroleer enige toepassing wanneer dit vir die eerste keer geloods of gewysig word teen sy databasis** van bekende malware en onveilige lêertipes. Wanneer jy 'n lêer aflaai deur sekere programme, soos Safari, Mail of Messages, skandeer XProtect outomaties die lêer. As dit enige bekende malware in sy databasis pas, sal XProtect die lêer **verhoed om uitgevoer te word** en jou waarsku vir die bedreiging.

Die XProtect-databasis word **gereeld deur Apple bygewerk** met nuwe malware-definisies, en hierdie opdaterings word outomaties afgelaai en geïnstalleer op jou Mac. Dit verseker dat XProtect altyd op hoogte is van die nuutste bekende bedreigings.

Dit is egter die moeite werd om te let dat **XProtect nie 'n volledige antivirusoplossing is nie**. Dit kontroleer slegs vir 'n spesifieke lys bekende bedreigings en voer nie op-toegang-skandering uit soos die meeste antivirusagteware nie.

Jy kan inligting oor die nuutste XProtect-opdatering kry deur die volgende uit te voer:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect is geleë op 'n SIP-beskermde plek by **/Library/Apple/System/Library/CoreServices/XProtect.bundle** en binne die bundel kan jy inligting vind wat XProtect gebruik:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Laat kode met daardie cdhashes toe om erfenisbevoegdhede te gebruik.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lys van plugins en uitbreidings wat verbied word om te laai via BundleID en TeamID of wat 'n minimum weergawe aandui.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara-reëls om malware op te spoor.
* **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-databasis met hasings van geblokkeerde toepassings en TeamIDs.

Let daarop dat daar 'n ander toepassing is in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** wat verband hou met XProtect en nie betrokke is by die Gatekeeper-proses nie.

#### Nie Gatekeeper nie

Let daarop dat Gatekeeper **nie elke keer uitgevoer word** wanneer jy 'n toepassing uitvoer nie, net _**AppleMobileFileIntegrity**_ (AMFI) sal slegs **uitvoerbare kodesignature** verifieer wanneer jy 'n toepassing uitvoer wat reeds deur Gatekeeper uitgevoer en geverifieer is.

Daarom was dit voorheen moontlik om 'n toepassing uit te voer om dit met Gatekeeper te laai, dan **nie-uitvoerbare lêers van die toepassing te wysig** (soos Electron asar- of NIB-lêers) en as geen ander beskermings in plek was nie, is die toepassing **uitgevoer** met die **boosaardige** byvoegings.

Dit is egter nou nie moontlik nie omdat macOS **wysiging van lêers binne toepassingsbundels voorkom**. As jy dus die [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) aanval probeer, sal jy vind dat dit nie meer moontlik is om dit te misbruik nie, want nadat jy die toepassing uitvoer om dit met Gatekeeper te laai, sal jy nie in staat wees om die bundel te wysig nie. En as jy byvoorbeeld die naam van die Contents-gids verander na NotCon (soos aangedui in die uitbuiting), en dan die hoofbinêre van die toepassing uitvoer om dit met Gatekeeper te laai, sal dit 'n fout veroorsaak en nie uitvoer nie.

### Gatekeeper-omseilings

Enige manier om Gatekeeper te omseil (om die gebruiker te laat iets aflaai en uitvoer wanneer Gatekeeper dit moet verbied) word beskou as 'n kwesbaarheid in macOS. Hierdie is 'n paar CVE's wat toegeken is aan tegnieke wat in die verlede gebruik is om Gatekeeper te omseil:

#### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Daar is waargeneem dat as die **Archive Utility** vir onttrekking gebruik word, ontvang lêers met **paaie wat 886 karakters oorskry** nie die com.apple.quarantine uitgebreide kenmerk nie. Hierdie situasie laat hierdie lêers onbedoeld toe om Gatekeeper se sekuriteitskontroles te **omseil**.

Kyk na die [**oorspronklike verslag**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) vir meer inligting.

#### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wanneer 'n toepassing met **Automator** geskep word, is die inligting oor wat dit moet uitvoer binne `application.app/Contents/document.wflow` en nie in die uitvoerbare lêer nie. Die uitvoerbare lêer is net 'n generiese Automator-binêre genaamd **Automator Application Stub**.

Daarom kon jy `application.app/Contents/MacOS/Automator\ Application\ Stub` **na 'n simboliese skakel na 'n ander Automator Application Stub binne die stelsel laat wys** en dit sal uitvoer wat binne `document.wflow` is (jou skripsie) **sonder om Gatekeeper te aktiveer** omdat die werklike uitvoerbare lêer nie die karantyn xattr het nie.

Voorbeeld van verwagte ligging: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Kyk na die [**oorspronklike verslag**](https://ronmasas.com/posts/bypass-macos-gatekeeper) vir meer inligting.

#### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In hierdie omseiling is 'n zip-lêer geskep met 'n toepassing wat begin om vanaf `application.app/Contents` te komprimeer in plaas van `application.app`. Daarom is die **karantynkenmerk** toegepas op al die **lêers vanaf `application.app/Contents`** maar **nie op `application.app`** nie, wat Gatekeeper was aan die ondersoek, dus is Gatekeeper omseil omdat toe `application.app` geaktiveer is, het dit **nie die karantynkenmerk gehad nie**.

```bash
zip -r test.app/Contents test.zip
```

Kyk na die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) vir meer inligting.

#### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Selfs al is die komponente verskillend, is die uitbuiting van hierdie kwesbaarheid baie soortgelyk aan die vorige een. In hierdie geval sal ons 'n Apple-argief genereer vanaf **`application.app/Contents`** sodat **`application.app` nie die karantynattribuut sal kry** wanneer dit gedekomprimeer word deur **Archive Utility**.

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Kyk na die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) vir meer inligting.

#### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kan gebruik word om te voorkom dat iemand 'n atribuut in 'n lêer skryf:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Verder kopieer die **AppleDouble** lêerformaat 'n lêer saam met sy ACEs.

In die [**bronkode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) is dit moontlik om te sien dat die ACL-teksvoorstelling wat binne die xattr genaamd **`com.apple.acl.text`** gestoor word, as ACL in die gedekomprimeerde lêer ingestel sal word. So, as jy 'n toepassing saamgepers het in 'n zip-lêer met die **AppleDouble** lêerformaat met 'n ACL wat voorkom dat ander xattrs daarin geskryf word... die karantyn xattr is nie in die toepassing ingestel nie:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Kyk na die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) vir meer inligting.

Let daarop dat dit ook uitgebuit kan word met AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

#### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Dit is ontdek dat **Google Chrome nie die karantyn atribuut** op afgelaaide lêers instel nie as gevolg van sekere interne macOS probleme.

#### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble lêerformate stoor die atribuute van 'n lêer in 'n aparte lêer wat begin met `._`, dit help om lêer atribuute **oor macOS masjiene** te kopieer. Dit is egter opgemerk dat nadat 'n AppleDouble lêer gedekomprimeer is, die lêer wat begin met `._` **nie die karantyn atribuut gekry het nie**.

{% code overflow="wrap" %}
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

Om 'n lêer te skep sonder die karantynatribuut, was dit **moontlik om Gatekeeper te omseil.** Die truuk was om 'n DMG-lêer-toepassing te skep deur die AppleDouble-naamkonvensie te gebruik (begin dit met `._`) en 'n **sigbare lêer as 'n simboliese skakel na hierdie verborge** lêer sonder die karantynatribuut te skep.\
Wanneer die **dmg-lêer uitgevoer word**, sal dit Gatekeeper **omseil omdat dit nie 'n karantynatribuut het nie**.

```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```

#### Voorkom Quarantine xattr

In 'n ".app" bundel, as die quarantine xattr nie daaraan toegevoeg word nie, sal **Gatekeeper nie geaktiveer word** wanneer dit uitgevoer word nie.



</details>
