# macOS Gatekeeper / Karantin / XProtect

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristup **najnovijoj verziji PEASS-a ili preuzimanje HackTricks-a u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grupi** ili **telegram grupi** ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova** na [**hacktricks repozitorijum**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijum**](https://github.com/carlospolop/hacktricks-cloud)

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Gatekeeper

**Gatekeeper** je bezbednosna funkcija razvijena za Mac operativne sisteme, dizajnirana da osigura da korisnici **pokreću samo pouzdani softver** na svojim sistemima. Funkcioniše tako što **validira softver** koji korisnik preuzima i pokušava da otvori sa **izvora van App Store-a**, kao što je aplikacija, dodatak ili instalacioni paket.

Ključni mehanizam Gatekeeper-a leži u njegovom **procesu verifikacije**. Proverava da li je preuzeti softver **potpisan od strane prepoznatljivog developera**, osiguravajući autentičnost softvera. Dodatno, utvrđuje da li je softver **notarisan od strane Apple-a**, potvrđujući da je lišen poznatog zlonamernog sadržaja i da nije menjan nakon notarizacije.

Pored toga, Gatekeeper jača kontrolu korisnika i bezbednost tako što **traži od korisnika odobrenje za otvaranje** preuzetog softvera prvi put. Ova zaštita pomaže u sprečavanju korisnika da slučajno pokrenu potencijalno štetan izvršni kod koji su možda greškom smatrali bezopasnim datotekama.

### Potpisi Aplikacija

Potpisi aplikacija, takođe poznati kao kodni potpisi, su ključna komponenta Apple-ove bezbednosne infrastrukture. Koriste se za **verifikaciju identiteta autora softvera** (developera) i kako bi se osiguralo da kod nije menjan od poslednjeg potpisa.

Evo kako to funkcioniše:

1. **Potpisivanje Aplikacije:** Kada developer bude spreman da distribuira svoju aplikaciju, on **potpisuje aplikaciju koristeći privatni ključ**. Taj privatni ključ je povezan sa **sertifikatom koji Apple izdaje developeru** kada se upiše u Apple Developer Program. Proces potpisivanja uključuje kreiranje kriptografskog heša svih delova aplikacije i šifrovanje ovog heša privatnim ključem developera.
2. **Distribucija Aplikacije:** Potpisana aplikacija se zatim distribuira korisnicima zajedno sa sertifikatom developera, koji sadrži odgovarajući javni ključ.
3. **Verifikacija Aplikacije:** Kada korisnik preuzme i pokuša da pokrene aplikaciju, njihov Mac operativni sistem koristi javni ključ iz sertifikata developera da dešifruje heš. Zatim ponovo izračunava heš na osnovu trenutnog stanja aplikacije i upoređuje ga sa dešifrovanim hešom. Ako se poklapaju, to znači da **aplikacija nije menjana** od trenutka kada ju je developer potpisao, i sistem dozvoljava aplikaciji da se pokrene.

Potpisi aplikacija su bitan deo Apple-ove Gatekeeper tehnologije. Kada korisnik pokuša da **otvori aplikaciju preuzetu sa interneta**, Gatekeeper verifikuje potpis aplikacije. Ako je potpisan sertifikatom koji je Apple izdao poznatom developeru i kod nije menjan, Gatekeeper dozvoljava aplikaciji da se pokrene. U suprotnom, blokira aplikaciju i obaveštava korisnika.

Počevši od macOS Catalina, **Gatekeeper takođe proverava da li je aplikacija notarizovana** od strane Apple-a, dodajući dodatni sloj bezbednosti. Proces notarizacije proverava aplikaciju na poznate bezbednosne probleme i zlonamerni kod, i ako ovi testovi prođu, Apple dodaje "ticket" aplikaciji koji Gatekeeper može da verifikuje.

#### Provera Potpisa

Prilikom provere nekog **uzorka malvera** uvek treba **proveriti potpis** binarnog koda jer bi **developer** koji ga je potpisao već mogao biti **povezan** sa **malverom**.
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
### Notarizacija

Apple-ov proces notarizacije služi kao dodatna zaštita kako bi se korisnici zaštitili od potencijalno štetnog softvera. Uključuje **razvojničko podnošenje njihove aplikacije na pregled** od strane **Apple-ove Notary Service**, što ne treba mešati sa App Review-om. Ova usluga je **automatizovan sistem** koji detaljno pregleda podneti softver radi otkrivanja **zlonamernog sadržaja** i potencijalnih problema sa potpisivanjem koda.

Ako softver **prođe** ovu inspekciju bez podizanja bilo kakvih zabrinutosti, Notary Service generiše notarizacioni tiket. Razvojničko je zatim potrebno da **priloži ovaj tiket uz svoj softver**, proces poznat kao 'stapling.' Nadalje, notarizacioni tiket se takođe objavljuje online gde Gatekeeper, Apple-ova sigurnosna tehnologija, može da mu pristupi.

Prilikom korisnikove prve instalacije ili izvršavanja softvera, postojanje notarizacionog tiketa - bilo da je prikačen za izvršnu datoteku ili pronađen online - **obaveštava Gatekeeper da je softver notarizovan od strane Apple-a**. Kao rezultat toga, Gatekeeper prikazuje opisnu poruku u dijalogu prvog pokretanja, ukazujući da je softver prošao provere na zlonamerni sadržaj od strane Apple-a. Ovaj proces time unapređuje korisničko poverenje u sigurnost softvera koji instaliraju ili pokreću na svojim sistemima.

### Enumeracija GateKeeper-a

GateKeeper je **nekoliko sigurnosnih komponenti** koje sprečavaju izvršavanje nepoverenih aplikacija i takođe je **jedna od komponenti**.

Moguće je videti **status** GateKeeper-a sa:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Imajte na umu da se provere potpisa GateKeeper-a vrše samo nad **datotekama sa atributom karantina**, a ne nad svakom datotekom.
{% endhint %}

GateKeeper će proveriti da li prema **postavkama i potpisu** binarni fajl može biti izvršen:

<figure><img src="../../../.gitbook/assets/image (1150).png" alt=""><figcaption></figcaption></figure>

Baza podataka koja čuva ovu konfiguraciju nalazi se u **`/var/db/SystemPolicy`**. Možete proveriti ovu bazu kao root korisnik sa:
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
Zapaženo je kako se pravilo završilo na "**App Store**", a drugo na "**Developer ID**" i da je u prethodnoj slici omogućeno izvršavanje aplikacija sa App Store-a i identifikovanih programera. Ako promenite tu postavku na App Store, pravila "**Notarized Developer ID**" će nestati.

Postoji i hiljade pravila tipa **GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Ovo su heševi koji potiču iz **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** i **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

Ili možete da nabrojite prethodne informacije sa:
```bash
sudo spctl --list
```
Opcije **`--master-disable`** i **`--global-disable`** komande **`spctl`** će potpuno **onemogućiti** provere potpisa:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Kada je potpuno omogućen, pojaviće se nova opcija:

<figure><img src="../../../.gitbook/assets/image (1151).png" alt=""><figcaption></figcaption></figure>

Moguće je **proveriti da li će aplikacija biti dozvoljena od strane GateKeeper-a** sa:
```bash
spctl --assess -v /Applications/App.app
```
Moguće je dodati nove pravila u GateKeeper kako bi se omogućilo izvršavanje određenih aplikacija pomoću:
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
### Karantin fajlovi

Prilikom **preuzimanja** aplikacije ili fajla, određene macOS **aplikacije** kao što su veb pregledači ili klijenti za e-poštu **dodaju prošireni atribut fajla**, poznat kao "**atribut karantina**," preuzetom fajlu. Ovaj atribut služi kao sigurnosna mera za označavanje fajla kao dolaznog sa nepouzdane izvora (internet), i potencijalno nosi rizike. Međutim, ne sve aplikacije dodaju ovaj atribut, na primer, uobičajeni BitTorrent klijenti softver obično zaobilaze ovaj proces.

**Prisustvo atributa karantina signalizira sigurnosnu funkciju macOS Gatekeeper-a kada korisnik pokuša da izvrši fajl**.

U slučaju kada **atribut karantina nije prisutan** (kao kod fajlova preuzetih putem nekih BitTorrent klijenata), **provere Gatekeeper-a se možda neće izvršiti**. Stoga, korisnici treba da budu oprezni prilikom otvaranja fajlova preuzetih sa manje sigurnih ili nepoznatih izvora.

{% hint style="info" %}
**Provera** validnosti potpisa koda je **resursno intenzivan** proces koji uključuje generisanje kriptografskih **heševa** koda i svih njegovih pakovanih resursa. Nadalje, provera validnosti sertifikata uključuje **online proveru** na Apple-ovim serverima da vidi da li je opozvan nakon što je izdat. Iz ovih razloga, potpuna provera potpisa koda i notarizacije je **nepraktična za pokretanje svaki put kada se pokrene aplikacija**.

Stoga, ove provere se **izvršavaju samo prilikom izvršavanja aplikacija sa atributom karantina**.
{% endhint %}

{% hint style="warning" %}
Ovaj atribut mora biti **postavljen od strane aplikacije koja kreira/preuzima** fajl.

Međutim, fajlovi koji su u pesku će imati ovaj atribut postavljen za svaki fajl koji kreiraju. I aplikacije koje nisu u pesku mogu ga postaviti same, ili specificirati [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) ključ u **Info.plist** koji će naterati sistem da postavi `com.apple.quarantine` prošireni atribut na kreirane fajlove,
{% endhint %}

Štaviše, svi fajlovi kreirani od strane procesa koji poziva **`qtn_proc_apply_to_self`** su u karantinu. Ili API **`qtn_file_apply_to_path`** dodaje atribut karantina na određenu putanju fajla.

Moguće je **proveriti njegov status i omogućiti/onemogućiti** (potreban je root) sa:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Takođe možete **pronaći da li datoteka ima prošireni atribut karantina** sa:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Proverite **vrednost** **proširenih** **atributa** i saznajte koja je aplikacija napisala atribut karantina sa:
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
Zapravo, proces "može postaviti karantinske zastave na datoteke koje kreira" (pokušao sam da primenim USER\_APPROVED zastavu na kreiranu datoteku, ali se ne primenjuje):

<details>

<summary>Izvorni kod primene karantinskih zastava</summary>
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

I **uklonite** taj atribut sa:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
I pronađite sve karantinovane datoteke sa:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Informacije o karantinu takođe se čuvaju u centralnoj bazi podataka koju upravlja LaunchServices u **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

#### **Quarantine.kext**

Kernel ekstenzija je dostupna samo putem **kernel keša na sistemu**; međutim, _možete_ preuzeti **Kernel Debug Kit sa https://developer.apple.com/**, koji će sadržati simbolizovanu verziju ekstenzije.

### XProtect

XProtect je ugrađena funkcija **anti-malver** zaštite u macOS-u. XProtect **proverava svaku aplikaciju kada se prvi put pokrene ili izmeni protiv svoje baze podataka** poznatih malvera i nesigurnih tipova fajlova. Kada preuzmete fajl putem određenih aplikacija, kao što su Safari, Mail ili Messages, XProtect automatski skenira fajl. Ako se poklapa sa bilo kojim poznatim malverom u svojoj bazi podataka, XProtect će **sprečiti pokretanje fajla** i obavestiti vas o pretnji.

Baza podataka XProtect-a se **redovno ažurira** od strane Apple-a sa novim definicijama malvera, a ova ažuriranja se automatski preuzimaju i instaliraju na vašem Mac-u. Ovo osigurava da je XProtect uvek ažuriran sa najnovijim poznatim pretnjama.

Međutim, vredi napomenuti da **XProtect nije potpuno opsežno antivirusno rešenje**. On samo proverava određeni spisak poznatih pretnji i ne vrši skeniranje pristupa kao većina antivirusnih softvera.

Možete dobiti informacije o najnovijem ažuriranju XProtect-a pokretanjem:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect se nalazi na SIP zaštićenoj lokaciji na **/Library/Apple/System/Library/CoreServices/XProtect.bundle** i unutar paketa možete pronaći informacije koje XProtect koristi:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Dozvoljava kod sa tim cdhash-ovima da koristi legacy privilegije.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista dodataka i ekstenzija koje su zabranjene za učitavanje putem BundleID-a i TeamID-a ili označavanje minimalne verzije.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara pravila za otkrivanje malvera.
* **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 baza podataka sa heševima blokiranih aplikacija i TeamID-ova.

Imajte na umu da postoji još jedna aplikacija u **`/Library/Apple/System/Library/CoreServices/XProtect.app`** koja je povezana sa XProtect-om, ali nije uključena u Gatekeeper proces.

### Ne Gatekeeper

{% hint style="danger" %}
Imajte na umu da Gatekeeper **ne pokreće se svaki put** kada pokrenete aplikaciju, samo će _**AppleMobileFileIntegrity**_ (AMFI) samo **verifikovati potpise izvršnog koda** kada pokrenete aplikaciju koja je već pokrenuta i verifikovana od strane Gatekeeper-a.
{% endhint %}

Stoga, ranije je bilo moguće pokrenuti aplikaciju da je kešira sa Gatekeeper-om, zatim **modifikovati neizvršne fajlove aplikacije** (kao što su Electron asar ili NIB fajlovi) i ako nisu postavljene druge zaštite, aplikacija je **izvršena** sa **zlonamernim** dodacima.

Međutim, sada to nije moguće jer macOS **sprečava modifikaciju fajlova** unutar paketa aplikacija. Dakle, ako pokušate [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) napad, primetićete da više nije moguće zloupotrebiti ga jer nakon što izvršite aplikaciju da je keširate sa Gatekeeper-om, nećete moći da modifikujete paket. I ako promenite na primer ime Contents direktorijuma u NotCon (kako je naznačeno u eksploataciji), a zatim izvršite glavni binarni fajl aplikacije da je keširate sa Gatekeeper-om, izazvaće grešku i neće se izvršiti.

## Bypass-ovi Gatekeeper-a

Bilo koji način zaobići Gatekeeper (uspeti da korisnik preuzme nešto i izvrši kada bi Gatekeeper trebao to zabraniti) smatra se ranjivošću u macOS-u. Ovo su neki CVE-ovi dodeljeni tehnikama koje su omogućile zaobilaženje Gatekeeper-a u prošlosti:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Primećeno je da ako se **Archive Utility** koristi za ekstrakciju, fajlovi sa **putanjama dužim od 886 karaktera** ne dobijaju prošireni atribut com.apple.quarantine. Ova situacija nenamerno omogućava tim fajlovima da **zaobiđu sigurnosne provere Gatekeeper-a**.

Proverite [**originalni izveštaj**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) za više informacija.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Kada se aplikacija kreira sa **Automator-om**, informacije o tome šta je potrebno za izvršenje su unutar `application.app/Contents/document.wflow` a ne u izvršnom fajlu. Izvršni fajl je samo generički Automator binarni fajl nazvan **Automator Application Stub**.

Stoga, mogli biste napraviti `application.app/Contents/MacOS/Automator\ Application\ Stub` da **pokazuje simboličkom vezom na drugi Automator Application Stub unutar sistema** i izvršiće ono što je unutar `document.wflow` (vaš skript) **bez pokretanja Gatekeeper-a** jer stvarni izvršni fajl nema karantinski xattr.

Primer očekivane lokacije: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Proverite [**originalni izveštaj**](https://ronmasas.com/posts/bypass-macos-gatekeeper) za više informacija.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

U ovom zaobilazenju, zip fajl je kreiran sa aplikacijom koja počinje sa kompresijom od `application.app/Contents` umesto `application.app`. Stoga, **karantinski atribut** je primenjen na sve **fajlove iz `application.app/Contents`** ali **ne na `application.app`**, što je Gatekeeper proveravao, tako da je Gatekeeper zaobiđen jer kada je `application.app` pokrenut, **nije imao karantinski atribut.**
```bash
zip -r test.app/Contents test.zip
```
Proverite [**originalni izveštaj**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) za više informacija.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Čak i ako su komponente različite, eksploatacija ove ranjivosti je vrlo slična prethodnoj. U ovom slučaju ćemo generisati Apple arhiv iz **`application.app/Contents`** tako da **`application.app` neće dobiti karantinski atribut** kada se dekompresuje pomoću **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Proverite [**originalni izveštaj**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) za više informacija.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** može se koristiti da se spreči bilo ko da piše atribut u fajl:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Osim toga, **AppleDouble** format datoteke kopira datoteku zajedno sa njenim ACE-ovima.

U [**izvornom kodu**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) moguće je videti da se ACL tekstualna reprezentacija čuva unutar xattr-a nazvanog **`com.apple.acl.text`** i da će biti postavljena kao ACL u dekompresovanoj datoteci. Dakle, ako ste kompresovali aplikaciju u zip datoteku sa **AppleDouble** formatom datoteke sa ACL-om koji sprečava pisanje drugih xattr-ova u nju... karantinski xattr nije postavljen u aplikaciju:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Proverite [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) za više informacija.

Imajte na umu da ovo takođe može biti iskorišćeno sa AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Otkriveno je da **Google Chrome nije postavljao atribut karantina** na preuzete datoteke zbog nekih internih problema u macOS-u.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble format datoteka čuva atribute datoteke u posebnoj datoteci koja počinje sa `._`, što pomaže u kopiranju atributa datoteke **između macOS mašina**. Međutim, primetno je da nakon dekompresije AppleDouble datoteke, datoteka koja počinje sa `._` **nije dobila atribut karantina**.

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

Mogućnost kreiranja datoteke koja neće imati postavljen atribut karantina, omogućavala je **bypass-ovanje Gatekeeper-a.** Trik je bio **kreirati DMG datoteku aplikacije** koristeći AppleDouble konvenciju imenovanja (početi sa `._`) i kreirati **vidljivu datoteku kao simboličku vezu ka ovoj skrivenoj** datoteci bez atributa karantina.\
Kada se **izvrši dmg datoteka**, budući da nema atributa karantina, **bypass-ovaće Gatekeeper.**
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
### uchg (iz ovog [razgovora](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

* Napravite direktorijum koji sadrži aplikaciju.
* Dodajte uchg aplikaciji.
* Kompresujte aplikaciju u tar.gz fajl.
* Pošaljite tar.gz fajl žrtvi.
* Žrtva otvara tar.gz fajl i pokreće aplikaciju.
* Gatekeeper ne proverava aplikaciju.

### Prevent Quarantine xattr

U ".app" paketu, ako se karantinski xattr ne doda, prilikom izvršavanja **Gatekeeper neće biti pokrenut**.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od početnika do stručnjaka sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
