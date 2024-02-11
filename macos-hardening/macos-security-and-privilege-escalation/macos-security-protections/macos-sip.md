# macOS SIP

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Podstawowe informacje**

**System Integrity Protection (SIP)** w macOS to mechanizm zaprojektowany w celu zapobiegania nawet najbardziej uprzywilejowanym użytkownikom wprowadzania nieautoryzowanych zmian w kluczowych folderach systemowych. Ta funkcja odgrywa kluczową rolę w utrzymaniu integralności systemu, ograniczając działania takie jak dodawanie, modyfikowanie lub usuwanie plików w chronionych obszarach. Główne foldery chronione przez SIP to:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Zasady regulujące zachowanie SIP są określone w pliku konfiguracyjnym znajdującym się pod adresem **`/System/Library/Sandbox/rootless.conf`**. W tym pliku ścieżki poprzedzone gwiazdką (*) są oznaczone jako wyjątki od rygorystycznych ograniczeń SIP.

Przykład poniżej:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Ten fragment sugeruje, że SIP zazwyczaj zabezpiecza katalog **`/usr`**, ale istnieją konkretne podkatalogi (`/usr/libexec/cups`, `/usr/local` i `/usr/share/man`), w których modyfikacje są dozwolone, o czym świadczy gwiazdka (*) poprzedzająca ich ścieżki.

Aby sprawdzić, czy katalog lub plik jest chroniony przez SIP, można użyć polecenia **`ls -lOd`**, aby sprawdzić obecność flagi **`restricted`** lub **`sunlnk`**. Na przykład:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
W tym przypadku flaga **`sunlnk`** oznacza, że sam katalog `/usr/libexec/cups` **nie może zostać usunięty**, chociaż pliki wewnątrz niego mogą być tworzone, modyfikowane lub usuwane.

Z drugiej strony:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Oto, flaga **`restricted`** wskazuje, że katalog `/usr/libexec` jest chroniony przez SIP. W chronionym przez SIP katalogu nie można tworzyć, modyfikować ani usuwać plików.

Ponadto, jeśli plik zawiera atrybut rozszerzony **`com.apple.rootless`**, również będzie on **chroniony przez SIP**.

**SIP ogranicza również inne działania roota**, takie jak:

* Ładowanie niezaufanych rozszerzeń jądra
* Uzyskiwanie portów zadań dla procesów podpisanych przez Apple
* Modyfikowanie zmiennych NVRAM
* Umożliwianie debugowania jądra

Opcje są przechowywane w zmiennej nvram jako bitflag (`csr-active-config` na Intelu i `lp-sip0` jest odczytywane z uruchomionego drzewa urządzenia dla ARM). Flagi można znaleźć w kodzie źródłowym XNU w pliku `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### Status SIP

Możesz sprawdzić, czy SIP jest włączony na swoim systemie za pomocą następującej komendy:
```bash
csrutil status
```
Jeśli chcesz wyłączyć SIP, musisz uruchomić komputer w trybie odzyskiwania (naciskając Command+R podczas uruchamiania), a następnie wykonać poniższą komendę:
```bash
csrutil disable
```
Jeśli chcesz zachować włączoną ochronę SIP, ale usunąć zabezpieczenia debugowania, możesz to zrobić za pomocą:
```bash
csrutil enable --without debug
```
### Inne ograniczenia

- **Zakazuje ładowania niepodpisanych rozszerzeń jądra** (kexts), zapewniając, że tylko zweryfikowane rozszerzenia współpracują z jądrem systemu.
- **Uniemożliwia debugowanie** procesów systemowych macOS, chroniąc podstawowe komponenty systemu przed nieautoryzowanym dostępem i modyfikacją.
- **Uniemożliwia narzędziom** takim jak dtrace inspekcję procesów systemowych, dalszo ochronę integralności działania systemu.

**[Dowiedz się więcej o informacjach na temat SIP w tej prezentacji](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship).**

## Ominięcie SIP

Ominięcie SIP umożliwia atakującemu:

- **Dostęp do danych użytkownika**: Odczytanie poufnych danych użytkownika, takich jak poczta, wiadomości i historia Safari ze wszystkich kont użytkowników.
- **Ominięcie TCC**: Bezpośrednia manipulacja bazą danych TCC (Transparency, Consent, and Control), aby uzyskać nieautoryzowany dostęp do kamery internetowej, mikrofonu i innych zasobów.
- **Ustanowienie trwałości**: Umieszczenie złośliwego oprogramowania w chronionych przez SIP lokalizacjach, co sprawia, że jest ono odporne na usunięcie, nawet przy uprawnieniach root. Obejmuje to również możliwość manipulacji narzędziem do usuwania złośliwego oprogramowania (MRT).
- **Ładowanie rozszerzeń jądra**: Mimo dodatkowych zabezpieczeń, ominięcie SIP upraszcza proces ładowania niepodpisanych rozszerzeń jądra.

### Pakiety instalacyjne

**Pakiety instalacyjne podpisane certyfikatem Apple** mogą ominąć jego ochronę. Oznacza to, że nawet pakiety podpisane przez standardowych deweloperów zostaną zablokowane, jeśli spróbują modyfikować chronione przez SIP katalogi.

### Nieistniejący plik SIP

Jednym potencjalnym lukiem jest to, że jeśli plik jest określony w **`rootless.conf`, ale nie istnieje obecnie**, można go utworzyć. Złośliwe oprogramowanie może wykorzystać to do **ustanowienia trwałości** w systemie. Na przykład złośliwy program może utworzyć plik .plist w `/System/Library/LaunchDaemons`, jeśli jest on wymieniony w `rootless.conf`, ale nie istnieje.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Uprawnienie **`com.apple.rootless.install.heritable`** umożliwia ominięcie SIP
{% endhint %}

#### Shrootless

[**Badacze z tego wpisu na blogu**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) odkryli podatność mechanizmu System Integrity Protection (SIP) w macOS, zwaną podatnością 'Shrootless'. Ta podatność dotyczy demona **`system_installd`**, który ma uprawnienie **`com.apple.rootless.install.heritable`**, umożliwiające dowolnemu z jego procesów potomnych ominięcie restrykcji systemu plików SIP.

Damon **`system_installd`** zainstaluje pakiety podpisane przez **Apple**.

Badacze odkryli, że podczas instalacji pakietu Apple (.pkg), **`system_installd`** **uruchamia** wszystkie skrypty **post-install** zawarte w pakiecie. Skrypty te są wykonywane przez domyślną powłokę **`zsh`**, która automatycznie **uruchamia** polecenia z pliku **`/etc/zshenv`**, jeśli istnieje, nawet w trybie nieinteraktywnym. To zachowanie może zostać wykorzystane przez atakujących: poprzez utworzenie złośliwego pliku `/etc/zshenv` i oczekiwanie na wywołanie `zsh` przez **`system_installd`**, mogą oni wykonywać dowolne operacje na urządzeniu.

Ponadto odkryto, że **`/etc/zshenv` może być używane jako ogólna technika ataku**, nie tylko do ominięcia SIP. Każdy profil użytkownika ma plik `~/.zshenv`, który zachowuje się tak samo jak `/etc/zshenv`, ale nie wymaga uprawnień root. Ten plik może być używany jako mechanizm trwałości, uruchamiany za każdym razem, gdy `zsh` się uruchamia, lub jako mechanizm podniesienia uprawnień. Jeśli użytkownik administrujący podnosi się do roota za pomocą `sudo -s` lub `sudo <polecenie>`, plik `~/.zshenv` zostanie uruchomiony, co skutkuje podniesieniem uprawnień do roota.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

W [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) odkryto, że ten sam proces **`system_installd`** nadal może być wykorzystywany, ponieważ umieszczał skrypt **post-install** w losowo nazwanym folderze chronionym przez SIP wewnątrz `/tmp`. Problem w tym, że **`/tmp` nie jest chronione przez SIP**, więc można było na nim **zamontować** obraz wirtualny, a następnie **instalator** umieściłby w nim skrypt **post-install**, **odmontował** obraz wirtualny, **ponownie utworzył** wszystkie **foldery** i **dodał** skrypt **post-install** z **payloadem** do wykonania.

#### [narzędzie fsck\_cs](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Zidentyfikowano podatność, w której **`fsck_cs`** został wprowadzony w błąd, powodując uszkodzenie kluczowego pliku ze względu na jego zdolność do śledzenia **linków symbolicznych**. Konkretnie, atakujący stworzyli link od _`/dev/diskX`_ do pliku `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Wykonanie **`fsck_cs`** na _`/dev/diskX`_ prowadziło do uszkodzenia `Info.plist`. Integralność tego pliku jest istotna dla System Integrity Protection (SIP) systemu operacyjnego, który kontroluje ładowanie rozszerzeń jądra. Po uszkodzeniu możliwość SIP do zarządzania wyłączeniami jądra jest zagrożona.

Polecenia do wykorzystania tej podatności to:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Wykorzystanie tej podatności ma poważne konsekwencje. Plik `Info.plist`, który normalnie odpowiada za zarządzanie uprawnieniami dla rozszerzeń jądra, staje się nieskuteczny. Dotyczy to również niemożności czarnolistowania określonych rozszerzeń, takich jak `AppleHWAccess.kext`. W rezultacie, z mechanizmem kontroli SIP wyłączonym, to rozszerzenie może być załadowane, co umożliwia nieautoryzowany odczyt i zapis do pamięci RAM systemu.


#### [Montowanie w chronionych folderach SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Było możliwe zamontowanie nowego systemu plików w **chronionych folderach SIP w celu obejścia ochrony**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Bypass upgradera (2016)](https://objective-see.org/blog/blog\_0x14.html)

System jest skonfigurowany do uruchamiania z wbudowanego obrazu dysku instalatora w `Install macOS Sierra.app` w celu aktualizacji systemu operacyjnego, wykorzystując narzędzie `bless`. Używane polecenie jest następujące:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bezpieczeństwo tego procesu może zostać naruszone, jeśli atakujący zmieni obraz aktualizacji (`InstallESD.dmg`) przed uruchomieniem. Strategia polega na podmianie dynamicznego ładowacza (dyld) na złośliwą wersję (`libBaseIA.dylib`). Ta zamiana powoduje wykonanie kodu atakującego podczas inicjowania instalatora.

Kod atakującego przejmuje kontrolę podczas procesu aktualizacji, wykorzystując zaufanie systemu do instalatora. Atak polega na zmianie obrazu `InstallESD.dmg` za pomocą metody swizzling, szczególnie celując w metodę `extractBootBits`. Pozwala to na wstrzyknięcie złośliwego kodu przed użyciem obrazu dysku.

Ponadto, w `InstallESD.dmg` znajduje się `BaseSystem.dmg`, który służy jako system plików korzenia kodu aktualizacji. Wstrzyknięcie dynamicznej biblioteki w to umożliwia działanie złośliwego kodu w procesie zdolnym do modyfikowania plików na poziomie systemu, znacznie zwiększając potencjał kompromitacji systemu.


#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

W tej prezentacji z [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) pokazano, jak **`systemmigrationd`** (który może ominąć SIP) wykonuje skrypt **bash** i **perl**, które mogą być wykorzystane za pomocą zmiennych środowiskowych **`BASH_ENV`** i **`PERL5OPT`**.

### **com.apple.rootless.install**

{% hint style="danger" %}
Uprawnienie **`com.apple.rootless.install`** umożliwia obejście SIP
{% endhint %}

Uprawnienie `com.apple.rootless.install` jest znane z omijania System Integrity Protection (SIP) w systemie macOS. Zostało to szczególnie wspomniane w kontekście [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

W tym konkretnym przypadku usługa XPC systemu znajdująca się w lokalizacji `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` posiada to uprawnienie. Pozwala to związanej z nią usłudze omijać ograniczenia SIP. Ponadto, ta usługa prezentuje metodę, która umożliwia przenoszenie plików bez stosowania żadnych środków bezpieczeństwa.


## Uszczelnione migawki systemu

Uszczelnione migawki systemu to funkcja wprowadzona przez Apple w **macOS Big Sur (macOS 11)** jako część mechanizmu **System Integrity Protection (SIP)**, zapewniająca dodatkową warstwę bezpieczeństwa i stabilności systemu. Są to w zasadzie tylko do odczytu wersje woluminu systemowego.

Oto bardziej szczegółowe spojrzenie:

1. **Niezmienny system**: Uszczelnione migawki systemu sprawiają, że wolumin systemowy macOS jest "niezmienny", co oznacza, że nie można go modyfikować. Zapobiega to nieautoryzowanym lub przypadkowym zmianom w systemie, które mogłyby naruszyć bezpieczeństwo lub stabilność systemu.
2. **Aktualizacje oprogramowania systemowego**: Podczas instalowania aktualizacji lub uaktualnień macOS tworzona jest nowa migawka systemu. Wolumin startowy macOS używa wtedy **APFS (Apple File System)**, aby przełączyć się na tę nową migawkę. Cały proces stosowania aktualizacji staje się bezpieczniejszy i bardziej niezawodny, ponieważ system zawsze może powrócić do poprzedniej migawki, jeśli coś pójdzie nie tak podczas aktualizacji.
3. **Rozdzielenie danych**: W połączeniu z koncepcją rozdzielenia woluminu danych i systemu wprowadzoną w macOS Catalina, funkcja uszczelnionych migawek systemu sprawia, że wszystkie dane i ustawienia są przechowywane na oddzielnym woluminie "**Data**". To rozdzielenie sprawia, że dane są niezależne od systemu, co upraszcza proces aktualizacji systemu i poprawia bezpieczeństwo systemu.

Pamiętaj, że te migawki są automatycznie zarządzane przez macOS i nie zajmują dodatkowej przestrzeni na dysku, dzięki możliwościom udostępniania przestrzeni w APFS. Ważne jest również zauważenie, że te migawki różnią się od migawek **Time Machine**, które są dostępne dla użytkownika i stanowią kopie zapasowe całego systemu.

### Sprawdź migawki

Polecenie **`diskutil apfs list`** wyświetla **szczegóły woluminów APFS** i ich układ:

<pre><code>+-- Kontener dysku3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   Odwołanie do kontenera APFS:     dysk3
|   Rozmiar (maksymalny):           494384795648 B (494,4 GB)
|   Pojemność wykorzystana przez woluminy:   219214536704 B (219,2 GB) (44,3% wykorzystane)
|   Pojemność nieprzydzielona:       275170258944 B (275,2 GB) (55,7% wolne)
|   |
|   +-&#x3C; Fizyczne urządzenie dysk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   Fizyczne urządzenie APFS:   dysk0s2
|   |   Rozmiar:                       494384795648 B (494,4 GB)
|   |
|   +-> Wolumin dysk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   Wolumin APFS (Rola):   dysk3s1 (System)
</strong>|   |   Nazwa:                      Macintosh HD (bez rozróżniania wielkości liter)
<strong>|   |   Punkt montowania:               /System/Volumes/Update/mnt1
</strong>|   |   Pojemność zużyta:         12819210240 B (12,8 GB)
|   |   Uszczelniony:                    Uszkodzony
|   |   FileVault:                 Tak (Odblokowany)
|   |   Szyfrowanie:                 Nie
|   |   |
|   |   Migawka:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Dysk migawki:             dysk3s1s1
<strong>|   |   Punkt montowania migawki:      /
</strong><strong>|   |   Migawka uszczelniona:           Tak
</strong>[...]
+-> Wolumin dysk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   Wolumin APFS (Rola):   dysk3s5 (Dane)
|   Nazwa:                      Macintosh HD - Data (bez rozróżniania wielkości liter)
<strong>    |   Punkt montowania:               /System/Volumes/Data
</strong><strong>    |   Pojemność zużyta:         412071784448 B (412,1 GB)
</strong>    |   Uszczelniony:                    Nie
|   FileVault:                 Tak (Odblokowany)
</code></pre>

W poprzednim wyniku można zobaczyć, że **dostępne dla użytkownika lokalizacje** są zamontowane pod `/System/Volumes/Data`.

Ponadto, **migawka woluminu systemowego macOS** jest zamontowana w `/` i jest **uszczelniona** (kryptograficznie podpisana przez system operacyjny). Jeśli SIP zostanie obejśnięty i zmodyfikowany, **system nie uruchomi się**.

Można również **sprawdzić, czy uszczelnienie jest włączone**, wykonując:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Ponadto, dysk ze snapshotem jest również zamontowany jako **tylko do odczytu**:
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
