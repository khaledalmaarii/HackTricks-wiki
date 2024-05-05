# macOS SIP

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to mechanizm **dark-web**, który oferuje **darmowe** funkcje do sprawdzania, czy firma lub jej klienci nie zostali **skompromitowani** przez **złośliwe oprogramowanie kradnące dane**.

Głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz sprawdzić ich stronę internetową i wypróbować ich silnik **za darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

***

## **Podstawowe informacje**

**Ochrona Integralności Systemu (SIP)** w macOS to mechanizm zaprojektowany w celu zapobiegania nawet najbardziej uprzywilejowanym użytkownikom dokonywania nieautoryzowanych zmian w kluczowych folderach systemowych. Ta funkcja odgrywa kluczową rolę w utrzymaniu integralności systemu poprzez ograniczanie działań takich jak dodawanie, modyfikowanie lub usuwanie plików w chronionych obszarach. Główne foldery chronione przez SIP to:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Zasady regulujące zachowanie SIP są określone w pliku konfiguracyjnym znajdującym się w **`/System/Library/Sandbox/rootless.conf`**. W tym pliku ścieżki poprzedzone gwiazdką (\*) są oznaczone jako wyjątki od zasadniczo rygorystycznych ograniczeń SIP.

Rozważ poniższy przykład:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Ten fragment sugeruje, że SIP zazwyczaj zabezpiecza katalog **`/usr`**, ale istnieją konkretne podkatalogi (`/usr/libexec/cups`, `/usr/local` i `/usr/share/man`), w których modyfikacje są dozwolone, o czym świadczy gwiazdka (\*) poprzedzająca ich ścieżki.

Aby sprawdzić, czy katalog lub plik jest chroniony przez SIP, możesz użyć polecenia **`ls -lOd`**, aby sprawdzić obecność flagi **`restricted`** lub **`sunlnk`**. Na przykład:
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
Oto flaga **`restricted`** wskazuje, że katalog `/usr/libexec` jest chroniony przez SIP. W katalogu chronionym przez SIP pliki nie mogą być tworzone, modyfikowane ani usuwane.

Co więcej, jeśli plik zawiera atrybut rozszerzony **`com.apple.rootless`**, ten plik również będzie **chroniony przez SIP**.

**SIP ogranicza również inne działania roota**, takie jak:

* Ładowanie niezaufanych rozszerzeń jądra
* Uzyskiwanie portów zadań dla procesów podpisanych przez Apple
* Modyfikowanie zmiennych NVRAM
* Umożliwianie debugowania jądra

Opcje są przechowywane w zmiennej nvram jako flaga bitowa (`csr-active-config` w przypadku Intel i `lp-sip0` jest odczytywane z drzewa urządzenia uruchomionego dla ARM). Flagi można znaleźć w kodzie źródłowym XNU w pliku `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (1192).png" alt=""><figcaption></figcaption></figure>

### Status SIP

Możesz sprawdzić, czy SIP jest włączony na swoim systemie za pomocą następującej komendy:
```bash
csrutil status
```
Jeśli musisz wyłączyć SIP, musisz ponownie uruchomić komputer w trybie odzyskiwania (naciskając Command+R podczas uruchamiania), a następnie wykonać poniższą komendę:
```bash
csrutil disable
```
Jeśli chcesz zachować włączony SIP, ale usunąć zabezpieczenia debugowania, możesz to zrobić za pomocą:
```bash
csrutil enable --without debug
```
### Inne Ograniczenia

* **Zakaz ładowania niepodpisanych rozszerzeń jądra** (kexts), zapewniając, że tylko zweryfikowane rozszerzenia współdziałają z jądrem systemowym.
* **Zapobiega debugowaniu** procesów systemowych macOS, zabezpieczając podstawowe składniki systemu przed nieautoryzowanym dostępem i modyfikacją.
* **Zakazuje narzędziom** takim jak dtrace inspekcji procesów systemowych, dodatkowo chroniąc integralność działania systemu.

[**Dowiedz się więcej o informacjach SIP w tej prezentacji**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

## Ominiecie SIP

Ominięcie SIP umożliwia atakującemu:

* **Dostęp do danych użytkownika**: Odczytanie wrażliwych danych użytkownika, takich jak poczta, wiadomości i historia przeglądania w Safari, we wszystkich kontach użytkowników.
* **Ominięcie TCC**: Bezpośrednie manipulowanie bazą danych TCC (Transparency, Consent, and Control) w celu udzielenia nieautoryzowanego dostępu do kamery internetowej, mikrofonu i innych zasobów.
* **Ustanowienie trwałości**: Umieszczenie złośliwego oprogramowania w chronionych przez SIP lokalizacjach, sprawiając, że jest ono odporne na usunięcie, nawet przy uprawnieniach root. Obejmuje to również potencjalną ingerencję w Narzędzie do Usuwania Złośliwego Oprogramowania (MRT).
* **Ładowanie Rozszerzeń Jądra**: Pomimo dodatkowych zabezpieczeń, ominięcie SIP upraszcza proces ładowania niepodpisanych rozszerzeń jądra.

### Pakiety Instalacyjne

**Pakiety instalacyjne podpisane certyfikatem Apple** mogą ominąć jego zabezpieczenia. Oznacza to, że nawet pakiety podpisane przez standardowych deweloperów zostaną zablokowane, jeśli spróbują modyfikować chronione przez SIP katalogi.

### Nieistniejący plik SIP

Potencjalną luką jest to, że jeśli plik jest określony w **`rootless.conf` ale obecnie nie istnieje**, może zostać utworzony. Złośliwe oprogramowanie mogłoby wykorzystać to do **ustanowienia trwałości** w systemie. Na przykład złośliwy program mógłby utworzyć plik .plist w `/System/Library/LaunchDaemons`, jeśli jest on wymieniony w `rootless.conf`, ale nie istnieje.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Uprawnienie **`com.apple.rootless.install.heritable`** pozwala na ominięcie SIP
{% endhint %}

#### [CVE-2019-8561](https://objective-see.org/blog/blog\_0x42.html) <a href="#cve" id="cve"></a>

Odkryto, że było możliwe **zamienienie pakietu instalacyjnego po weryfikacji kodu** przez system, a następnie system zainstalowałby złośliwy pakiet zamiast oryginalnego. Ponieważ te działania były wykonywane przez **`system_installd`**, pozwalało to na ominięcie SIP.

#### [CVE-2020–9854](https://objective-see.org/blog/blog\_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Jeśli pakiet był instalowany z obrazu zamontowanego lub zewnętrznego dysku, **instalator** wykonywałby binarny plik z **tego systemu plików** (zamiast z chronionej przez SIP lokalizacji), powodując, że **`system_installd`** wykonywałby dowolny binarny plik.

#### CVE-2021-30892 - Shrootless

[**Badacze z tego wpisu na blogu**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) odkryli lukę w mechanizmie Integrity Protection System (SIP) macOS, zwaną luką 'Shrootless'. Ta luka koncentruje się wokół demona **`system_installd`**, który ma uprawnienie, **`com.apple.rootless.install.heritable`**, pozwalające na ominięcie restrykcji systemu plików SIP przez dowolne z jego procesów potomnych.

Demon **`system_installd`** będzie instalował pakiety podpisane przez **Apple**.

Badacze odkryli, że podczas instalacji pakietu podpisanego przez Apple (.pkg), **`system_installd`** **wykonuje** wszystkie **skrypty po instalacji** zawarte w pakiecie. Te skrypty są wykonywane przez domyślną powłokę, **`zsh`**, która automatycznie **wykonuje** polecenia z pliku **`/etc/zshenv`**, jeśli istnieje, nawet w trybie nieinteraktywnym. To zachowanie mogło zostać wykorzystane przez atakujących: tworząc złośliwy plik `/etc/zshenv` i czekając, aż **`system_installd` wywoła `zsh`**, mogli wykonać dowolne operacje na urządzeniu.

Ponadto odkryto, że **`/etc/zshenv` mogło być używane jako ogólna technika ataku**, nie tylko do ominięcia SIP. Każdy profil użytkownika ma plik `~/.zshenv`, który zachowuje się tak samo jak `/etc/zshenv`, ale nie wymaga uprawnień root. Ten plik mógłby być użyty jako mechanizm trwałości, uruchamiający się za każdym razem, gdy `zsh` się uruchamia, lub jako mechanizm podnoszenia uprawnień. Jeśli użytkownik administrujący podnosi uprawnienia do roota za pomocą `sudo -s` lub `sudo <polecenie>`, plik `~/.zshenv` zostanie uruchomiony, efektywnie podnosząc uprawnienia do roota.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

W [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) odkryto, że ten sam proces **`system_installd`** nadal mógł być wykorzystywany, ponieważ umieszczał **skrypt po instalacji w losowo nazwanym folderze chronionym przez SIP wewnątrz `/tmp`**. Problem polegał na tym, że **`/tmp` samo w sobie nie jest chronione przez SIP**, więc było możliwe **zamontowanie** na nim **obrazu wirtualnego**, a następnie **instalator** umieściłby tam **skrypt po instalacji**, **odmontował** obraz wirtualny, **ponownie utworzył** wszystkie **foldery** i **dodał** skrypt **po instalacji** z **ładunkiem** do wykonania.

#### [narzędzie fsck\_cs](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Zidentyfikowano lukę, w której **`fsck_cs`** został wprowadzony w błąd, aby uszkodzić istotny plik, ze względu na jego zdolność do śledzenia **linków symbolicznych**. Konkretnie, atakujący stworzyli link od _`/dev/diskX`_ do pliku `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Wykonanie **`fsck_cs`** na _`/dev/diskX`_ doprowadziło do uszkodzenia `Info.plist`. Integralność tego pliku jest kluczowa dla Systemu Integrity Protection (SIP) systemu operacyjnego, który kontroluje ładowanie rozszerzeń jądra. Po uszkodzeniu, zdolność SIP do zarządzania wykluczeniami jądra jest zagrożona.

Polecenia do wykorzystania tej luki to:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Wykorzystanie tej podatności ma poważne konsekwencje. Plik `Info.plist`, zwykle odpowiedzialny za zarządzanie uprawnieniami do rozszerzeń jądra, staje się nieskuteczny. Dotyczy to niemożności umieszczenia na czarnej liście określonych rozszerzeń, takich jak `AppleHWAccess.kext`. W rezultacie, przy mechanizmie kontroli SIP wyłączonym, to rozszerzenie może być załadowane, co umożliwia nieautoryzowany odczyt i zapis do pamięci RAM systemu.

#### [Montowanie nad chronionymi folderami SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Było możliwe zamontowanie nowego systemu plików nad **chronionymi folderami SIP w celu ominięcia ochrony**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog\_0x14.html)

System jest ustawiony na rozruch z wbudowanego obrazu dysku instalacyjnego w `Install macOS Sierra.app` w celu aktualizacji systemu operacyjnego, wykorzystując narzędzie `bless`. Użyta komenda jest następująca:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bezpieczeństwo tego procesu może zostać zagrożone, jeśli atakujący zmieni obraz aktualizacji (`InstallESD.dmg`) przed uruchomieniem. Strategia polega na zastąpieniu dynamicznego ładowacza (dyld) złośliwą wersją (`libBaseIA.dylib`). Ta zamiana powoduje wykonanie kodu atakującego podczas inicjowania instalatora.

Kod atakującego przejmuje kontrolę podczas procesu aktualizacji, wykorzystując zaufanie systemu do instalatora. Atak polega na zmianie obrazu `InstallESD.dmg` poprzez metodę swizzling, szczególnie kierując się do metody `extractBootBits`. Pozwala to na wstrzyknięcie złośliwego kodu przed użyciem obrazu dysku.

Co więcej, w `InstallESD.dmg` znajduje się `BaseSystem.dmg`, który służy jako system plików główny kodu aktualizacji. Wstrzyknięcie dynamicznej biblioteki pozwala złośliwemu kodowi działać w procesie zdolnym do zmiany plików na poziomie systemu operacyjnego, znacząco zwiększając potencjał kompromitacji systemu.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

W tej prezentacji z [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) pokazano, jak **`systemmigrationd`** (który może ominąć SIP) wykonuje skrypt **bash** i **perl**, które mogą być wykorzystane za pomocą zmiennych środowiskowych **`BASH_ENV`** i **`PERL5OPT`**.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Jak [**opisano w tym wpisie na blogu**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), skrypt `postinstall` z pakietów `InstallAssistant.pkg` był wykonywany:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
i było możliwe utworzenie symlinka w `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`, który pozwalał użytkownikowi **odblokować dowolny plik, omijając ochronę SIP**.

### **com.apple.rootless.install**

{% hint style="danger" %}
Uprawnienie **`com.apple.rootless.install`** pozwala ominąć SIP
{% endhint %}

Uprawnienie `com.apple.rootless.install` jest znane z omijania System Integrity Protection (SIP) w macOS. Zostało to szczególnie wspomniane w kontekście [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

W tym konkretnym przypadku usługa XPC systemu znajdująca się w `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` posiada to uprawnienie. Pozwala to powiązanemu procesowi omijać ograniczenia SIP. Ponadto ta usługa prezentuje metodę, która pozwala na przenoszenie plików bez stosowania żadnych środków bezpieczeństwa.

## Uszczelnione migawki systemu

Uszczelnione migawki systemu to funkcja wprowadzona przez Apple w **macOS Big Sur (macOS 11)** jako część mechanizmu **System Integrity Protection (SIP)**, zapewniająca dodatkową warstwę bezpieczeństwa i stabilności systemu. Są to w zasadzie wersje tylko do odczytu woluminu systemowego.

Oto bardziej szczegółowe spojrzenie:

1. **System niemutowalny**: Uszczelnione migawki systemu sprawiają, że wolumin systemowy macOS jest "niemutowalny", co oznacza, że nie można go modyfikować. Zapobiega to nieautoryzowanym lub przypadkowym zmianom w systemie, które mogłyby zagrażać bezpieczeństwu lub stabilności systemu.
2. **Aktualizacje oprogramowania systemowego**: Podczas instalowania aktualizacji lub uaktualnień macOS tworzona jest nowa migawka systemu. Wolumin startowy macOS używa wtedy **APFS (Apple File System)** do przełączenia się na tę nową migawkę. Cały proces stosowania aktualizacji staje się bezpieczniejszy i bardziej niezawodny, ponieważ system zawsze może powrócić do poprzedniej migawki, jeśli coś pójdzie nie tak podczas aktualizacji.
3. **Separacja danych**: W połączeniu z koncepcją separacji woluminu danych i systemu wprowadzoną w macOS Catalina, funkcja uszczelnionych migawek systemu zapewnia, że wszystkie dane i ustawienia są przechowywane na osobnym woluminie "**Dane**". Ta separacja sprawia, że dane są niezależne od systemu, co upraszcza proces aktualizacji systemu i zwiększa bezpieczeństwo systemu.

Pamiętaj, że te migawki są automatycznie zarządzane przez macOS i nie zajmują dodatkowej przestrzeni na dysku, dzięki możliwościom współdzielenia przestrzeni w APFS. Ważne jest również zauważenie, że te migawki różnią się od **migawek Time Machine**, które są dostępnymi dla użytkownika kopiami zapasowymi całego systemu.

### Sprawdź migawki

Polecenie **`diskutil apfs list`** wyświetla **szczegóły woluminów APFS** i ich układ:

<pre><code>+-- Kontener dysku3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   Odwołanie do kontenera APFS:     dysk3
|   Rozmiar (pojemność maksymalna):  494384795648 B (494,4 GB)
|   Pojemność używana przez woluminy:  219214536704 B (219,2 GB) (użyto 44,3%)
|   Pojemność nieprzydzielona:       275170258944 B (275,2 GB) (wolne 55,7%)
|   |
|   +-&#x3C; Magazyn fizyczny dysku0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   Fizyczny magazyn APFS:   dysk0s2
|   |   Rozmiar:                       494384795648 B (494,4 GB)
|   |
|   +-> Wolumin dysku3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   Wolumin APFS (Rola):   dysk3s1 (System)
</strong>|   |   Nazwa:                      Macintosh HD (bez rozróżniania wielkości liter)
<strong>|   |   Punkt montowania:               /System/Volumes/Update/mnt1
</strong>|   |   Pojemność zużyta:         12819210240 B (12,8 GB)
|   |   Uszczelniony:                    Uszkodzony
|   |   FileVault:                 Tak (Odblokowany)
|   |   Szyfrowany:                 Nie
|   |   |
|   |   Migawka:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Dysk migawki:             dysk3s1s1
<strong>|   |   Punkt montowania migawki:      /
</strong><strong>|   |   Migawka uszczelniona:           Tak
</strong>[...]
+-> Wolumin dysku3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   Wolumin APFS (Rola):   dysk3s5 (Dane)
|   Nazwa:                      Macintosh HD - Data (bez rozróżniania wielkości liter)
<strong>    |   Punkt montowania:               /System/Volumes/Data
</strong><strong>    |   Pojemność zużyta:         412071784448 B (412,1 GB)
</strong>    |   Uszczelniony:                    Nie
|   FileVault:                 Tak (Odblokowany)
</code></pre>

W poprzednim wyniku można zobaczyć, że **dostępne dla użytkownika lokalizacje** są zamontowane pod `/System/Volumes/Data`.

Co więcej, **migawka woluminu systemowego macOS** jest zamontowana w `/` i jest **uszczelniona** (podpisana kryptograficznie przez system operacyjny). Dlatego jeśli SIP zostanie zignorowany i zmodyfikowany, **system nie uruchomi się**.

Możliwe jest również **zweryfikowanie, czy uszczelnienie jest włączone**, wykonując:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Ponadto, dysk migawkowy jest również zamontowany jako **tylko do odczytu**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana przez **dark web**, która oferuje **darmowe** funkcje do sprawdzenia, czy firma lub jej klienci nie zostali **skompromitowani** przez **złośliwe oprogramowanie kradnące informacje**.

Ich głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz odwiedzić ich stronę internetową i wypróbować ich silnik za **darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
