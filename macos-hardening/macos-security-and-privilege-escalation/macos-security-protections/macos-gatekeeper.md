# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><strong>Zacznij naukę hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Gatekeeper

**Gatekeeper** to funkcja zabezpieczeń opracowana dla systemów operacyjnych Mac, zaprojektowana w celu zapewnienia, że użytkownicy **uruchamiają tylko zaufane oprogramowanie** na swoich systemach. Działa poprzez **weryfikację oprogramowania**, które użytkownik pobiera i próbuje otworzyć z **źródeł spoza App Store**, takich jak aplikacja, wtyczka lub pakiet instalacyjny.

Kluczowym mechanizmem Gatekeepera jest jego **proces weryfikacji**. Sprawdza, czy pobrane oprogramowanie jest **podpisane przez uznawanego dewelopera**, zapewniając autentyczność oprogramowania. Ponadto sprawdza, czy oprogramowanie jest **zatwierdzone przez Apple**, potwierdzając, że jest wolne od znanych treści złośliwych i nie zostało zmodyfikowane po zatwierdzeniu.

Dodatkowo, Gatekeeper wzmacnia kontrolę użytkownika i bezpieczeństwo, **prosząc użytkowników o zatwierdzenie otwarcia** pobranego oprogramowania po raz pierwszy. Ta ochrona pomaga zapobiec przypadkowemu uruchomieniu potencjalnie szkodliwego kodu wykonywalnego, który użytkownik mógł pomylić z nieszkodliwym plikiem danych.

### Podpisy Aplikacji

Podpisy aplikacji, znane również jako podpisy kodu, są kluczowym elementem infrastruktury bezpieczeństwa Apple. Służą do **weryfikacji tożsamości autora oprogramowania** (dewelopera) oraz zapewnienia, że kod nie został zmieniony od czasu ostatniego podpisania.

Oto jak to działa:

1. **Podpisywanie Aplikacji:** Gdy deweloper jest gotowy do dystrybucji swojej aplikacji, **podpisuje aplikację przy użyciu klucza prywatnego**. Ten klucz prywatny jest powiązany z **certyfikatem, który Apple wydaje deweloperowi** podczas zapisywania się do programu dla deweloperów Apple. Proces podpisywania polega na utworzeniu kryptograficznego skrótu wszystkich części aplikacji i zaszyfrowaniu tego skrótu kluczem prywatnym dewelopera.
2. **Dystrybucja Aplikacji:** Podpisana aplikacja jest następnie dystrybuowana do użytkowników wraz z certyfikatem dewelopera, który zawiera odpowiadający klucz publiczny.
3. **Weryfikacja Aplikacji:** Gdy użytkownik pobiera i próbuje uruchomić aplikację, ich system operacyjny Mac używa klucza publicznego z certyfikatu dewelopera do odszyfrowania skrótu. Następnie ponownie oblicza skrót na podstawie bieżącego stanu aplikacji i porównuje go z odszyfrowanym skrótem. Jeśli się zgadzają, oznacza to, że **aplikacja nie została zmodyfikowana** od czasu podpisania przez dewelopera, i system zezwala na uruchomienie aplikacji.

Podpisy aplikacji są istotną częścią technologii Gatekeeper firmy Apple. Gdy użytkownik próbuje **otworzyć aplikację pobraną z internetu**, Gatekeeper weryfikuje podpis aplikacji. Jeśli jest on podpisany certyfikatem wydanym przez znanego dewelopera Apple i kod nie został zmieniony, Gatekeeper zezwala na uruchomienie aplikacji. W przeciwnym razie blokuje aplikację i informuje użytkownika.

Począwszy od macOS Catalina, **Gatekeeper sprawdza również, czy aplikacja została zatwierdzona** przez Apple, dodając dodatkową warstwę zabezpieczeń. Proces notaryzacji sprawdza aplikację pod kątem znanych problemów z bezpieczeństwem i kodu złośliwego, a jeśli te testy zostaną zaliczone, Apple dodaje bilet do aplikacji, który Gatekeeper może zweryfikować.

#### Sprawdzanie Podpisów

Podczas sprawdzania niektórych **próbek złośliwego oprogramowania** zawsze należy **sprawdzić podpis** binarny, ponieważ **deweloper**, który go podpisał, może być już **powiązany** z **złośliwym oprogramowaniem**.
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
### Notaryzacja

Proces notaryzacji firmy Apple stanowi dodatkowe zabezpieczenie mające na celu ochronę użytkowników przed potencjalnie szkodliwym oprogramowaniem. Polega on na **dostarczeniu przez dewelopera swojej aplikacji do zbadania** przez **Usługę Notarialną Apple**, która nie powinna być mylona z Recenzją Aplikacji. Ta usługa to **zautomatyzowany system**, który analizuje przesłane oprogramowanie pod kątem **zawartości szkodliwej** oraz ewentualnych problemów z podpisem kodu.

Jeśli oprogramowanie **przejdzie** tę inspekcję bez podniesienia jakichkolwiek wątpliwości, Usługa Notarialna generuje bilet notaryzacyjny. Następnie deweloper musi **dołączyć ten bilet do swojego oprogramowania**, co jest procesem znanym jako 'zszywanie'. Ponadto bilet notaryzacyjny jest również publikowany online, gdzie Gatekeeper, technologia bezpieczeństwa Apple, może uzyskać do niego dostęp.

Podczas pierwszej instalacji lub uruchomienia oprogramowania przez użytkownika, istnienie biletu notaryzacyjnego - czy to zszytego z plikiem wykonywalnym, czy znalezionego online - **informuje Gatekeepera, że oprogramowanie zostało notaryzowane przez Apple**. W rezultacie Gatekeeper wyświetla opisową wiadomość w początkowym oknie uruchamiania, informującą, że oprogramowanie zostało poddane sprawdzeniom pod kątem zawartości szkodliwej przez Apple. Ten proces zwiększa zaufanie użytkowników do bezpieczeństwa oprogramowania, które instalują lub uruchamiają na swoich systemach.

### Wyliczanie GateKeeper

GateKeeper to zarówno **kilka komponentów bezpieczeństwa**, które zapobiegają uruchamianiu niezaufanych aplikacji, jak i **jeden z komponentów**.

Można sprawdzić **status** GateKeepera za pomocą:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Należy zauważyć, że sprawdzanie sygnatury GateKeeper jest wykonywane tylko dla **plików z atrybutem kwarantanny**, a nie dla każdego pliku.
{% endhint %}

GateKeeper sprawdzi, czy zgodnie z **preferencjami i sygnaturą** można uruchomić plik binarny:

<figure><img src="../../../.gitbook/assets/image (1147).png" alt=""><figcaption></figcaption></figure>

Baza danych przechowująca tę konfigurację znajduje się w **`/var/db/SystemPolicy`**. Możesz sprawdzić tę bazę danych jako root za pomocą:
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
Zauważ, jak pierwsza reguła zakończyła się na "**App Store**", a druga na "**Developer ID**", a w poprzednim obrazie było **włączone wykonywanie aplikacji ze sklepu App Store i zidentyfikowanych deweloperów**. Jeśli **zmienisz** to ustawienie na App Store, reguły "**Notarized Developer ID**" znikną.

Istnieje także tysiące reguł **typu GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
To są hashe pochodzące z **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** oraz **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

Lub możesz wyświetlić poprzednie informacje za pomocą:
```bash
sudo spctl --list
```
Opcje **`--master-disable`** i **`--global-disable`** polecenia **`spctl`** całkowicie wyłączą te kontrole podpisów:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Gdy jest w pełni włączony, pojawi się nowa opcja:

<figure><img src="../../../.gitbook/assets/image (1148).png" alt=""><figcaption></figcaption></figure>

Możliwe jest **sprawdzenie, czy aplikacja zostanie zezwolona przez GateKeeper** za pomocą:
```bash
spctl --assess -v /Applications/App.app
```
Możliwe jest dodanie nowych reguł w GateKeeperze, aby zezwolić na wykonanie określonych aplikacji za pomocą:
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
### Pliki w kwarantannie

Po **pobraniu** aplikacji lub pliku, określone **aplikacje macOS**, takie jak przeglądarki internetowe czy klienty poczty elektronicznej, **dołączają rozszerzony atrybut pliku**, powszechnie znany jako "**flaga kwarantanny**", do pobranego pliku. Ten atrybut działa jako środek bezpieczeństwa, **oznaczając plik** jako pochodzący z niezaufanego źródła (internetu) i potencjalnie niosący ryzyko. Jednak nie wszystkie aplikacje dołączają ten atrybut, na przykład popularne oprogramowanie klientów BitTorrent zazwyczaj omija ten proces.

**Obecność flagi kwarantanny sygnalizuje funkcję bezpieczeństwa Gatekeeper macOS, gdy użytkownik próbuje uruchomić plik**.

W przypadku gdy **flaga kwarantanny nie jest obecna** (jak w przypadku plików pobranych za pomocą niektórych klientów BitTorrent), **sprawdzenia Gatekeepera mogą nie zostać wykonane**. Dlatego użytkownicy powinni zachować ostrożność przy otwieraniu plików pobranych z mniej bezpiecznych lub nieznanych źródeł.

{% hint style="info" %}
**Sprawdzanie** **ważności** podpisów kodu to **proces wymagający dużych zasobów**, który obejmuje generowanie kryptograficznych **skrótów** kodu i wszystkich jego pakietowanych zasobów. Ponadto, sprawdzenie ważności certyfikatu polega na **sprawdzeniu online** u serwerów Apple, czy został on unieważniony po wydaniu. Z tych powodów pełne sprawdzenie podpisu kodu i notyfikacji jest **niepraktyczne do uruchamiania za każdym razem, gdy aplikacja jest uruchamiana**.

Dlatego te sprawdzenia są **wykonywane tylko podczas uruchamiania aplikacji z atrybutem w kwarantannie**.
{% endhint %}

{% hint style="warning" %}
Ten atrybut musi być **ustawiony przez aplikację tworzącą/pobierającą** plik.

Jednak pliki, które są zabezpieczone piaskownicą, będą miały ten atrybut ustawiony dla każdego pliku, który tworzą. Aplikacje niebędące w piaskownicy mogą samodzielnie go ustawić lub określić klucz [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) w pliku **Info.plist**, co spowoduje, że system ustawia rozszerzony atrybut `com.apple.quarantine` na utworzonych plikach.
{% endhint %}

Możliwe jest **sprawdzenie jego statusu i włączenie/wyłączenie** (wymagane uprawnienia roota) za pomocą:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Możesz również **sprawdzić, czy plik ma atrybut kwarantanny** za pomocą:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Sprawdź **wartość** **rozszerzonych** **atrybutów** i dowiedz się, która aplikacja napisała atrybut kwarantanny za pomocą:
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
Faktycznie proces "może ustawić flagi kwarantanny dla tworzonych plików" (próbowałem zastosować flagę USER\_APPROVED w utworzonym pliku, ale nie została ona zastosowana):

<details>

<summary>Kod źródłowy zastosowania flag kwarantanny</summary>
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
I znajdź wszystkie zablokowane pliki za pomocą:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Informacje o kwarantannie są również przechowywane w centralnej bazie danych zarządzanej przez LaunchServices w **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

#### **Quarantine.kext**

Rozszerzenie jądra jest dostępne tylko poprzez **pamięć podręczną jądra w systemie**; jednak można pobrać **Kernel Debug Kit z https://developer.apple.com/**, który zawiera zsymbolizowaną wersję rozszerzenia.

### XProtect

XProtect to wbudowana funkcja **antywirusowa** w macOS. XProtect **sprawdza każdą aplikację podczas pierwszego uruchomienia lub modyfikacji w stosunku do swojej bazy danych** znanych złośliwych oprogramowań i niebezpiecznych typów plików. Gdy pobierasz plik za pomocą określonych aplikacji, takich jak Safari, Mail lub Wiadomości, XProtect automatycznie skanuje plik. Jeśli pasuje do znanego złośliwego oprogramowania w swojej bazie danych, XProtect **uniemożliwi uruchomienie pliku** i powiadomi Cię o zagrożeniu.

Baza danych XProtect jest **regularnie aktualizowana** przez Apple nowymi definicjami złośliwego oprogramowania, a te aktualizacje są automatycznie pobierane i instalowane na Twoim Macu. Zapewnia to, że XProtect zawsze jest aktualny z najnowszymi znanymi zagrożeniami.

Warto jednak zauważyć, że **XProtect nie jest pełnoprawnym rozwiązaniem antywirusowym**. Sprawdza tylko określoną listę znanych zagrożeń i nie wykonuje skanowania w czasie rzeczywistym, jak większość oprogramowania antywirusowego.

Możesz uzyskać informacje o najnowszej aktualizacji XProtect, uruchamiając:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect znajduje się w chronionym przez SIP miejscu w **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, a wewnątrz bundla znajdziesz informacje, których XProtect używa:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Pozwala kodowi z tymi cdhashes na korzystanie z przestarzałych uprawnień.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista wtyczek i rozszerzeń, które są niedozwolone do załadowania za pomocą BundleID i TeamID lub wskazujących minimalną wersję.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Zasady Yara do wykrywania złośliwego oprogramowania.
* **`XProtect.bundle/Contents/Resources/gk.db`**: Baza danych SQLite3 z haszami zablokowanych aplikacji i TeamIDs.

Zauważ, że istnieje inna aplikacja w **`/Library/Apple/System/Library/CoreServices/XProtect.app`** związana z XProtect, która nie jest związana z procesem Gatekeeper.

### Nie Gatekeeper

{% hint style="danger" %}
Zauważ, że Gatekeeper **nie jest uruchamiany za każdym razem**, gdy uruchamiasz aplikację, tylko _**AppleMobileFileIntegrity**_ (AMFI) będzie tylko **weryfikować podpisy kodu wykonywalnego** podczas uruchamiania aplikacji, która została już uruchomiona i zweryfikowana przez Gatekeeper.
{% endhint %}

Dlatego wcześniej było możliwe uruchomienie aplikacji, aby ją zbuforować za pomocą Gatekeeper, a następnie **zmodyfikowanie plików nie wykonywalnych aplikacji** (takich jak pliki Electron asar lub NIB) i jeśli nie było innych zabezpieczeń, aplikacja była **uruchamiana** z **złośliwymi** dodatkami.

Jednak teraz to nie jest możliwe, ponieważ macOS **zapobiega modyfikowaniu plików** wewnątrz bundli aplikacji. Więc jeśli spróbujesz ataku [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), zobaczysz, że nie jest już możliwe nadużycie, ponieważ po uruchomieniu aplikacji w celu zbuforowania jej za pomocą Gatekeeper, nie będziesz mógł modyfikować bundla. A jeśli zmienisz na przykład nazwę katalogu Contents na NotCon (jak wskazano w exploicie), a następnie uruchomisz główny plik binarny aplikacji, aby zbuforować go za pomocą Gatekeeper, spowoduje to błąd i nie zostanie uruchomiony.

## Ominięcia Gatekeepera

Każda metoda ominięcia Gatekeepera (umiejętność sprawienia, aby użytkownik pobrał coś i uruchomił to, gdy Gatekeeper powinien tego zabronić) jest uważana za lukę w zabezpieczeniach macOS. Oto kilka CVE przypisanych do technik, które pozwalały na ominięcie Gatekeepera w przeszłości:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Zauważono, że jeśli **Archive Utility** jest używane do rozpakowywania, pliki o **ścieżkach przekraczających 886 znaków** nie otrzymują rozszerzonego atrybutu com.apple.quarantine. Sytuacja ta nieumyślnie pozwala tym plikom na **ominięcie kontroli bezpieczeństwa** Gatekeepera.

Sprawdź [**oryginalny raport**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) po więcej informacji.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Gdy aplikacja jest tworzona za pomocą **Automatora**, informacje o tym, co musi wykonać, znajdują się w `application.app/Contents/document.wflow`, a nie w wykonywalnym pliku. Wykonywalny plik to tylko ogólny binarny Automator o nazwie **Automator Application Stub**.

Dlatego można sprawić, że `application.app/Contents/MacOS/Automator\ Application\ Stub` **wskaże symbolicznym odnośnikiem na inny Automator Application Stub w systemie**, a to spowoduje wykonanie tego, co jest wewnątrz `document.wflow` (twój skrypt) **bez wywoływania Gatekeepera**, ponieważ rzeczywisty plik wykonywalny nie ma atrybutu kwarantanny.

Przykładowa oczekiwana lokalizacja: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Sprawdź [**oryginalny raport**](https://ronmasas.com/posts/bypass-macos-gatekeeper) po więcej informacji.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

W tym ominięciu został utworzony plik zip z aplikacją zaczynającą kompresję od `application.app/Contents` zamiast od `application.app`. Dlatego **atrybut kwarantanny** został zastosowany do wszystkich **plików z `application.app/Contents`** ale **nie do `application.app`**, który był sprawdzany przez Gatekeepera, więc Gatekeeper został ominięty, ponieważ gdy uruchomiono `application.app`, **nie miał atrybutu kwarantanny.**
```bash
zip -r test.app/Contents test.zip
```
Sprawdź [**oryginalny raport**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) po więcej informacji.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Nawet jeśli komponenty są różne, wykorzystanie tej podatności jest bardzo podobne do poprzedniej. W tym przypadku wygenerujemy Archiwum Apple z **`application.app/Contents`**, więc **`application.app` nie otrzyma atrybutu kwarantanny** po rozpakowaniu przez **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Sprawdź [**oryginalny raport**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) po więcej informacji.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** może być używane do zapobiegania zapisywania atrybutu w pliku:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Ponadto format pliku **AppleDouble** kopiuje plik wraz z jego ACE.

W [**kodzie źródłowym**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) można zobaczyć, że reprezentacja tekstowa ACL przechowywana w xattr o nazwie **`com.apple.acl.text`** zostanie ustawiona jako ACL w zdekompresowanym pliku. Dlatego jeśli spakowano aplikację do pliku zip w formacie pliku **AppleDouble** z ACL, które uniemożliwia zapisywanie innych xattr do niego... xattr kwarantanny nie został ustawiony w aplikacji:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Sprawdź [**oryginalny raport**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) po więcej informacji.

Należy zauważyć, że to również może być wykorzystane z AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Odkryto, że **Google Chrome nie ustawiał atrybutu kwarantanny** dla pobranych plików z powodu pewnych wewnętrznych problemów systemu macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Formaty plików AppleDouble przechowują atrybuty pliku w osobnym pliku zaczynającym się od `._`, co pomaga skopiować atrybuty pliku **między maszynami z systemem macOS**. Jednak zauważono, że po rozpakowaniu pliku AppleDouble, plik zaczynający się od `._` **nie otrzymywał atrybutu kwarantanny**.

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

Mając możliwość utworzenia pliku, który nie będzie miał ustawionego atrybutu kwarantanny, było **możliwe do ominięcia Gatekeepera.** Trikiem było **utworzenie aplikacji pliku DMG** przy użyciu konwencji nazewnictwa AppleDouble (zaczynając od `._`) i utworzenie **widocznego pliku jako dowiązanie symboliczne do tego ukrytego** pliku bez atrybutu kwarantanny.\
Gdy **plik dmg zostanie uruchomiony**, ponieważ nie ma atrybutu kwarantanny, **omija Gatekeepera**.
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
### Zapobieganie atrybutowi xattr kwarantanny

W paczce ".app", jeśli atrybut xattr kwarantanny nie jest do niej dodany, to **Gatekeeper nie zostanie uruchomiony**.
