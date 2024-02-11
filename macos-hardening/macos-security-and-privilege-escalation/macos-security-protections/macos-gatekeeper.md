# macOS Gatekeeper / Karantini / XProtect

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? au ungependa kupata **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Gatekeeper

**Gatekeeper** ni kipengele cha usalama kilichotengenezwa kwa mfumo wa uendeshaji wa Mac, kimeundwa ili kuhakikisha kuwa watumiaji **wanatumia tu programu za kuaminika** kwenye mifumo yao. Inafanya kazi kwa **kuthibitisha programu** ambayo mtumiaji anapakua na kujaribu kuifungua kutoka **vyanzo nje ya Duka la App**, kama programu, programu-jalizi, au pakiti ya usanidi.

Mfumo muhimu wa Gatekeeper uko katika **uthibitisho** wake. Inachunguza ikiwa programu iliyopakuliwa ime **sainiwa na msanidi wa kutambuliwa**, ikidhibitisha uhalali wa programu. Zaidi ya hayo, inathibitisha ikiwa programu ime **thibitishwa na Apple**, ikithibitisha kuwa haina maudhui mabaya yanayojulikana na haijabadilishwa baada ya kuthibitishwa.

Zaidi ya hayo, Gatekeeper inaimarisha udhibiti na usalama wa mtumiaji kwa **kuwauliza watumiaji kuidhinisha ufunguzi** wa programu iliyopakuliwa kwa mara ya kwanza. Kinga hii inasaidia kuzuia watumiaji kwa bahati mbaya kuendesha nambari inayoweza kuwa na madhara ambayo wangeweza kuchukulia kama faili ya data isiyo na madhara.

### Saini za Programu

Saini za programu, pia hujulikana kama saini za nambari, ni sehemu muhimu ya miundombinu ya usalama ya Apple. Hutumiwa kwa **uthibitisho wa utambulisho wa mwandishi wa programu** (msanidi) na kuhakikisha kuwa nambari haijabadilishwa tangu iliposainiwa mara ya mwisho.

Hivi ndivyo inavyofanya kazi:

1. **Kusaini Programu:** Wakati msanidi anapojisikia kupeleka programu yao, wanaisaini kwa kutumia **funguo ya faragha**. Funguo hii ya faragha inahusishwa na **cheti ambacho Apple inatoa kwa msanidi** wanapojiandikisha kwenye Programu ya Watengenezaji ya Apple. Mchakato wa kusaini unahusisha kuunda hash ya kriptografia ya sehemu zote za programu na kuiweka hash hii kwa kutumia funguo ya faragha ya msanidi.
2. **Kusambaza Programu:** Programu iliyosainiwa inasambazwa kwa watumiaji pamoja na cheti cha msanidi, ambacho kinafunguo ya umma inayolingana.
3. **Kuthibitisha Programu:** Wakati mtumiaji anapopakua na kujaribu kuendesha programu, mfumo wa uendeshaji wa Mac hutumia funguo ya umma kutoka kwenye cheti cha msanidi kufungua hash. Kisha inahesabu upya hash kulingana na hali ya sasa ya programu na kulinganisha na hash iliyofunguliwa. Ikiwa zinafanana, inamaanisha **programu haijabadilishwa** tangu msanidi aliposaini, na mfumo unaruhusu programu iendelee kufanya kazi.

Saini za programu ni sehemu muhimu ya teknolojia ya Gatekeeper ya Apple. Wakati mtumiaji anajaribu **kufungua programu iliyopakuliwa kutoka kwenye mtandao**, Gatekeeper inathibitisha saini ya programu. Ikiwa ime sainiwa na cheti kilichotolewa na Apple kwa msanidi anayejulikana na nambari haijabadilishwa, Gatekeeper inaruhusu programu ifanye kazi. Vinginevyo, inazuia programu na kuwajulisha mtumiaji.

Kuanzia macOS Catalina, **Gatekeeper pia inachunguza ikiwa programu imepata kibali** kutoka kwa Apple, ikiongeza safu ya ziada ya usalama. Mchakato wa kibali huchunguza programu kwa masuala ya usalama yanayojulikana na nambari mbaya, na ikiwa ukaguzi huu unapita, Apple inaongeza tiketi kwenye programu ambayo Gatekeeper inaweza kuthibitisha.

#### Angalia Saini

Unapochunguza **sampuli ya programu hasidi**, unapaswa daima **angalia saini** ya faili ya binary kwani **msanidi** aliyetoa saini inaweza tayari **kuhusishwa** na **programu hasidi**.
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
### Notarization

Mchakato wa kuhakiki wa Apple unatumika kama kinga ya ziada kulinda watumiaji kutokana na programu inayoweza kuwa na madhara. Inahusisha **developer kuwasilisha maombi yao kwa uchunguzi** na **Huduma ya Notary ya Apple**, ambayo haipaswi kuchanganywa na Ukaguzi wa Programu. Huduma hii ni **mfumo wa kiotomatiki** ambao huchunguza programu iliyowasilishwa kwa uwepo wa **maudhui mabaya** na masuala yoyote yanayohusiana na uthibitishaji wa nambari.

Ikiwa programu inapita uchunguzi huu bila kuibua wasiwasi wowote, Huduma ya Notary huzalisha tiketi ya uhakiki. Kisha, developer anatakiwa **kuambatanisha tiketi hii kwenye programu yao**, mchakato unaojulikana kama 'stapling.' Zaidi ya hayo, tiketi ya uhakiki pia huwekwa mtandaoni ambapo Gatekeeper, teknolojia ya usalama ya Apple, inaweza kuipata.

Wakati mtumiaji anapoinstall au kuzindua programu kwa mara ya kwanza, uwepo wa tiketi ya uhakiki - iwe imeambatanishwa na programu au imepatikana mtandaoni - **inamjulisha Gatekeeper kwamba programu imehakikiwa na Apple**. Kama matokeo, Gatekeeper huonyesha ujumbe maelezo katika dirisha la kuzindua awali, ukionyesha kuwa programu imefanyiwa uchunguzi wa maudhui mabaya na Apple. Hivyo, mchakato huu unaimarisha imani ya mtumiaji katika usalama wa programu wanazoinstall au kukimbia kwenye mfumo wao.

### Kuhesabu GateKeeper

GateKeeper ni **sehemu kadhaa za usalama** ambazo zinazuia programu zisizoaminika kuzinduliwa na pia ni **moja ya sehemu hizo**.

Inawezekana kuona **hali** ya GateKeeper kwa kutumia:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Tafadhali kumbuka kuwa ukaguzi wa saini wa GateKeeper unafanywa tu kwa **faili zenye sifa ya Karantini**, sio kwa kila faili.
{% endhint %}

GateKeeper itahakiki ikiwa kulingana na **mapendeleo na saini**, faili ya binary inaweza kutekelezwa:

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

Database ambayo inahifadhi usanidi huu iko katika **`/var/db/SystemPolicy`**. Unaweza kuangalia database hii kama root kwa kutumia:
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
Tafadhali angalia jinsi sheria ya kwanza ilivyomalizika katika "**App Store**" na ya pili katika "**Developer ID**" na kwamba katika picha iliyotangulia ilikuwa **imeidhinishwa kutekeleza programu kutoka kwenye Duka la App na watengenezaji waliothibitishwa**. Ikiwa **ubadilishe** mipangilio hiyo kuwa Duka la App, sheria za "**Notarized Developer ID" zitaondoka**.

Pia kuna maelfu ya sheria za **aina ya GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Hizi ni hashi zinazotoka **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** na **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

Au unaweza kuorodhesha habari iliyotangulia na:
```bash
sudo spctl --list
```
Chaguo **`--master-disable`** na **`--global-disable`** ya **`spctl`** itazima kabisa ukaguzi wa saini hizi:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Wakati inapowezeshwa kabisa, chaguo jipya litatokea:

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

Inawezekana **kuangalia ikiwa Programu itaruhusiwa na GateKeeper** kwa:
```bash
spctl --assess -v /Applications/App.app
```
Niwezekana kuongeza sheria mpya kwenye GateKeeper ili kuruhusu utekelezaji wa programu fulani kwa:
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
### Mafaili ya Karantini

Baada ya **kupakua** programu au faili, programu maalum za macOS kama vile vivinjari vya wavuti au wateja wa barua pepe **huambatanisha sifa ya ziada ya faili**, inayojulikana kama "**bendera ya karantini**," kwenye faili iliyopakuliwa. Sifa hii inafanya kazi kama hatua ya usalama kuonyesha faili kama inayotoka kwenye chanzo ambacho hakijathibitishwa (mtandao), na inaweza kuwa na hatari. Hata hivyo, si programu zote huambatanisha sifa hii, kwa mfano, programu za wateja wa BitTorrent kawaida hupuuza mchakato huu.

**Uwepo wa bendera ya karantini unawasilisha kipengele cha usalama cha Gatekeeper cha macOS wakati mtumiaji anajaribu kutekeleza faili**.

Katika kesi ambapo **bendera ya karantini haipo** (kama ilivyo kwa faili zilizopakuliwa kupitia baadhi ya wateja wa BitTorrent), **uchunguzi wa Gatekeeper huenda usifanyike**. Hivyo, watumiaji wanapaswa kuwa makini wanapofungua faili zilizopakuliwa kutoka vyanzo visivyo salama au visivyojulikana.

{% hint style="info" %}
**Kuangalia** uhalali wa saini za nambari ni mchakato wenye **gharama kubwa** ambao unajumuisha kuzalisha **hashi za kriptografia** za nambari na rasilimali zake zote zilizounganishwa. Zaidi ya hayo, kuangalia uhalali wa cheti kunahusisha kufanya **uchunguzi mtandaoni** kwenye seva za Apple ili kuona ikiwa imetenguliwa baada ya kutolewa. Kwa sababu hizi, uchunguzi kamili wa saini za nambari na uthibitishaji hauwezekani kufanyika kila wakati programu inapoanzishwa.

Kwa hiyo, uchunguzi huu **hufanyika tu wakati wa kutekeleza programu zilizo na sifa ya karantini**.
{% endhint %}

{% hint style="warning" %}
Sifa hii lazima **iwekwe na programu inayounda/kupakua** faili.

Hata hivyo, faili zilizowekwa kwenye sanduku la mchanga zitakuwa na sifa hii iliyowekwa kwa kila faili wanayounda. Na programu zisizowekwa kwenye sanduku la mchanga zinaweza kuweka sifa hii wenyewe, au kufafanua ufunguo wa [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) kwenye **Info.plist** ambayo itafanya mfumo kuweka sifa ya ziada ya `com.apple.quarantine` kwenye faili zilizoundwa,
{% endhint %}

Inawezekana **kuangalia hali yake na kuwezesha/lemaza** (inahitaji mizizi) kwa:
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
Angalia **thamani** ya **vipengele vya ziada** na tafuta programu iliyoandika sifa ya karantini na:
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
Kwa kweli, mchakato "unaweza kuweka alama za karantini kwenye faili ambazo huziumba" (nilijaribu kuweka bendera ya USER_APPROVED kwenye faili niliyounda lakini haikuiweka):

<details>

<summary>Msimbo wa Chanzo wa kuweka alama za karantini</summary>
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

Na **ondoa** sifa hiyo na:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Na pata faili zote zilizofungwa karantini na:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Maelezo ya karantini pia hifadhiwa katika database kuu inayosimamiwa na LaunchServices katika **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

#### **Quarantine.kext**

Kernel extension inapatikana tu kupitia **cache ya kernel kwenye mfumo**; hata hivyo, unaweza kupakua **Kernel Debug Kit kutoka https://developer.apple.com/**, ambayo itakuwa na toleo lililosimbwa la ugani.

### XProtect

XProtect ni kipengele cha **kuzuia programu hasidi** kilichojengwa ndani ya macOS. XProtect **huchunguza programu yoyote wakati inapoanzishwa au kuhaririwa kwa mara ya kwanza dhidi ya database yake** ya programu hasidi inayojulikana na aina za faili hatari. Unapopakua faili kupitia programu fulani, kama vile Safari, Mail, au Messages, XProtect huchunguza faili hiyo kiotomatiki. Ikiwa inalingana na programu hasidi inayojulikana katika database yake, XProtect ita**zuia faili hiyo kutekelezwa** na kukuarifu kuhusu tishio.

Database ya XProtect **inasasishwa mara kwa mara** na Apple na ufafanuzi mpya wa programu hasidi, na sasisho hizi hupakuliwa na kusakinishwa kiotomatiki kwenye Mac yako. Hii inahakikisha kuwa XProtect daima iko na habari za hivi karibuni kuhusu vitisho vinavyojulikana.

Hata hivyo, ni muhimu kuzingatia kuwa **XProtect sio suluhisho kamili la antivirus**. Inachunguza tu orodha maalum ya vitisho vinavyojulikana na haitoi uchunguzi wa moja kwa moja kama programu nyingi za antivirus.

Unaweza kupata habari kuhusu sasisho la XProtect la hivi karibuni kwa kukimbia:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect iko kwenye eneo lililolindwa na SIP kwenye **/Library/Apple/System/Library/CoreServices/XProtect.bundle** na ndani ya bundle unaweza kupata habari ambazo XProtect inatumia:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Inaruhusu nambari zenye cdhashes hizo kutumia ruhusa za zamani.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Orodha ya programu na nyongeza ambazo haziruhusiwi kupakia kupitia BundleID na TeamID au kuonyesha toleo la chini.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Sheria za Yara za kugundua programu hasidi.
* **`XProtect.bundle/Contents/Resources/gk.db`**: Hifadhidata ya SQLite3 na hash za programu zilizozuiliwa na TeamIDs.

Tafadhali kumbuka kuwa kuna Programu nyingine katika **`/Library/Apple/System/Library/CoreServices/XProtect.app`** inayohusiana na XProtect ambayo haishiriki katika mchakato wa Gatekeeper.

### Sio Gatekeeper

{% hint style="danger" %}
Tafadhali kumbuka kuwa Gatekeeper **haitasasishwa kila wakati** unapotekeleza programu, tu _**AppleMobileFileIntegrity**_ (AMFI) itathibitisha tu **saini za nambari zinazoweza kutekelezwa** wakati unapotekeleza programu ambayo tayari imekwisha tekelezwa na kuthibitishwa na Gatekeeper.
{% endhint %}

Kwa hivyo, hapo awali ilikuwa inawezekana kutekeleza programu ili kuichache na Gatekeeper, kisha **kubadilisha faili zisizo za utekelezaji za programu** (kama vile faili za Electron asar au NIB) na ikiwa hakuna ulinzi mwingine uliowekwa, programu ilitekelezwa na **kuongeza** zenye **uovu**.

Walakini, sasa hii haiwezekani kwa sababu macOS **inazuia kubadilisha faili** ndani ya vifurushi vya programu. Kwa hivyo, ikiwa unajaribu shambulio la [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), utagundua kuwa sasa haiwezekani kuitumia tena kwa sababu baada ya kutekeleza programu ili kuichache na Gatekeeper, hautaweza kubadilisha vifurushi. Na ikiwa unabadilisha, kwa mfano, jina la saraka ya Maudhui kuwa NotCon (kama ilivyoelezwa katika shambulio), na kisha kutekeleza programu kuu ya kuichache na Gatekeeper, itasababisha kosa na haitatekelezwa.

## Mbinu za Kupita kwa Gatekeeper

Njia yoyote ya kuepuka Gatekeeper (kufanikiwa kufanya mtumiaji kupakua kitu na kuitekeleza wakati Gatekeeper inapaswa kuzuia) inachukuliwa kama udhaifu katika macOS. Hizi ni baadhi ya CVE zilizotengwa kwa mbinu ambazo ziliruhusu kuepuka Gatekeeper hapo awali:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Ilionekana kuwa ikiwa **Archive Utility** inatumika kwa kuchambua, faili zenye **njia zinazozidi wahusika 886** hazipati sifa ya ziada ya com.apple.quarantine. Hali hii kwa bahati mbaya inaruhusu faili hizo kuzunguka **ukaguzi wa usalama wa Gatekeeper**.

Angalia [**ripoti ya asili**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) kwa habari zaidi.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wakati programu inaundwa na **Automator**, habari kuhusu kile inachohitaji kutekeleza iko ndani ya `application.app/Contents/document.wflow` sio kwenye faili ya utekelezaji. Faili ya utekelezaji ni tu utekelezaji wa kawaida wa Automator unaoitwa **Automator Application Stub**.

Kwa hivyo, unaweza kufanya `application.app/Contents/MacOS/Automator\ Application\ Stub` **ielekeze kwa njia ya kiungo ishara kwa Automator Application Stub nyingine ndani ya mfumo** na itatekeleza kile kilicho ndani ya `document.wflow` (script yako) **bila kusababisha Gatekeeper** kwa sababu utekelezaji halisi hauna sifa ya karantini.&#x20;

Mfano wa eneo lililotarajiwa: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Angalia [**ripoti ya asili**](https://ronmasas.com/posts/bypass-macos-gatekeeper) kwa habari zaidi.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Katika mbinu hii ya kuepuka, faili ya zip iliumbwa na programu ilianza kubana kutoka `application.app/Contents` badala ya `application.app`. Kwa hivyo, **sifa ya karantini** ilitekelezwa kwa **faili zote kutoka `application.app/Contents`** lakini **sio kwa `application.app`**, ambayo ndiyo Gatekeeper ilikuwa ikikagua, kwa hivyo Gatekeeper ilipuuzwa kwa sababu wakati `application.app` ilipotumiwa **haikuwa na sifa ya karantini**.
```bash
zip -r test.app/Contents test.zip
```
Angalia [**ripoti ya asili**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) kwa maelezo zaidi.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Hata kama sehemu ni tofauti, utumiaji wa kasoro hii ni sawa na ile ya awali. Katika kesi hii, tutazalisha Apple Archive kutoka **`application.app/Contents`** ili **`application.app` isipate sifa ya karantini** wakati inapojazwa na **Archive Utility**.
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

Katika [**msimbo wa chanzo**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), inawezekana kuona kuwa uwakilishi wa maandishi wa ACL uliowekwa ndani ya xattr inayoitwa **`com.apple.acl.text`** utawekwa kama ACL katika faili iliyofunguliwa. Kwa hivyo, ikiwa umefunga programu katika faili ya zip kwa muundo wa **AppleDouble** na ACL ambayo inazuia xattrs nyingine kuandikwa ndani yake... xattr ya karantini haikuwekwa katika programu:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Angalia [**ripoti ya asili**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa maelezo zaidi.

Tafadhali kumbuka kuwa hii pia inaweza kudukuliwa na AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Iligunduliwa kuwa **Google Chrome haikuweka sifa ya karantini** kwa faili zilizopakuliwa kutokana na matatizo ya ndani ya macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Muundo wa faili za AppleDouble huhifadhi sifa za faili katika faili tofauti inayoanza na `._`, hii husaidia kuiga sifa za faili **katika mashine za macOS**. Walakini, iligundulika kuwa baada ya kufungua faili ya AppleDouble, faili inayoanza na `._` **haikuwekewa sifa ya karantini**.

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

Kwa kuweza kuunda faili ambayo haitakuwa na sifa ya karantini ilikuwa **inawezekana kudukua Gatekeeper**. Hila ilikuwa **kuunda faili ya DMG ya programu** kwa kutumia utaratibu wa jina la AppleDouble (ianze na `._`) na kuunda **faili inayoonekana kama kiungo cha ishara kwa faili hii iliyofichwa** bila sifa ya karantini.\
Wakati **faili ya dmg inatekelezwa**, kwa kuwa haina sifa ya karantini, itapita **Gatekeeper**.
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
### Zuia Karantini xattr

Katika kifurushi cha ".app" ikiwa karantini xattr haijaongezwa, wakati inatekelezwa **Gatekeeper haitaanzishwa**.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
