# Wykorzystywanie instalatorów macOS

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje o plikach Pkg

Plik instalatora macOS (znany również jako plik `.pkg`) to format pliku używany przez macOS do **dystrybucji oprogramowania**. Te pliki są jak **pudełko, które zawiera wszystko, czego potrzebuje kawałek oprogramowania**, aby zainstalować i działać poprawnie.

Sam plik pakietu to archiwum, które zawiera **hierarchię plików i katalogów, które zostaną zainstalowane na docelowym** komputerze. Może również zawierać **skrypty**, które wykonują zadania przed i po instalacji, takie jak konfigurowanie plików konfiguracyjnych lub usuwanie starych wersji oprogramowania.

### Hierarchia

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: Dostosowania (tytuł, tekst powitalny...) i skrypt/sprawdzanie instalacji
* **PackageInfo (xml)**: Informacje, wymagania instalacji, lokalizacja instalacji, ścieżki do skryptów do uruchomienia
* **Bill of materials (bom)**: Lista plików do zainstalowania, aktualizacji lub usunięcia wraz z uprawnieniami do plików
* **Payload (archiwum CPIO skompresowane gzipem)**: Pliki do zainstalowania w `install-location` z PackageInfo
* **Skrypty (archiwum CPIO skompresowane gzipem)**: Skrypty przed i po instalacji oraz inne zasoby wyodrębnione do tymczasowego katalogu w celu wykonania.
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
## Podstawowe informacje o plikach DMG

Pliki DMG, czyli Apple Disk Images, to format pliku używany przez system macOS firmy Apple do obrazów dysków. Plik DMG to w zasadzie **montowalny obraz dysku** (zawiera własny system plików), który zawiera surowe dane blokowe, zwykle skompresowane i czasami zaszyfrowane. Gdy otworzysz plik DMG, macOS **montuje go jak fizyczny dysk**, umożliwiając dostęp do jego zawartości.

### Hierarchia

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

Hierarchia pliku DMG może być różna w zależności od zawartości. Jednak w przypadku plików DMG aplikacji, zazwyczaj ma ona następującą strukturę:

* Poziom główny: To jest korzeń obrazu dysku. Zazwyczaj zawiera aplikację i ewentualnie odnośnik do folderu Applications.
* Aplikacja (.app): To jest właściwa aplikacja. W systemie macOS aplikacja to zazwyczaj paczka zawierająca wiele pojedynczych plików i folderów, które tworzą aplikację.
* Odnośnik do aplikacji: To jest skrót do folderu Applications w systemie macOS. Jego celem jest ułatwienie instalacji aplikacji. Możesz przeciągnąć plik .app na ten skrót, aby zainstalować aplikację.

## Eskalacja uprawnień poprzez nadużycie plików pkg

### Wykonywanie z publicznych katalogów

Jeśli skrypt instalacyjny przed lub po instalacji jest na przykład wykonywany z **`/var/tmp/Installerutil`**, atakujący może kontrolować ten skrypt i wykorzystać go do eskalacji uprawnień za każdym razem, gdy zostanie wykonany. Innym podobnym przykładem jest:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Jest to [publiczna funkcja](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), którą wiele programów instalacyjnych i aktualizatorów wywołuje, aby **wykonać coś jako root**. Ta funkcja przyjmuje jako parametr **ścieżkę** do **pliku**, który ma zostać **wykonany**, jednak jeśli atakujący może **zmodyfikować** ten plik, będzie mógł **nadużyć** jego wykonania jako root do **eskalacji uprawnień**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Aby uzyskać więcej informacji, sprawdź tę prezentację: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Wykonanie poprzez montowanie

Jeśli instalator zapisuje pliki w `/tmp/fixedname/bla/bla`, możliwe jest **utworzenie montażu** nad `/tmp/fixedname` bez właściciela, dzięki czemu można **modyfikować dowolny plik podczas instalacji** w celu nadużycia procesu instalacji.

Przykładem tego jest **CVE-2021-26089**, który umożliwiał **nadpisanie skryptu okresowego**, aby uzyskać wykonanie jako root. Aby uzyskać więcej informacji, zapoznaj się z prezentacją: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg jako złośliwe oprogramowanie

### Pusta ładowność

Możliwe jest wygenerowanie pliku **`.pkg`** zawierającego **skrypty przed i po instalacji** bez żadnej ładowności.

### JS w pliku Distribution xml

Możliwe jest dodanie tagów **`<script>`** w pliku **distribution xml** pakietu, a ten kod zostanie wykonany i może **wykonywać polecenia** za pomocą **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Odwołania

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Uzyskaj [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**The PEASS Family**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
