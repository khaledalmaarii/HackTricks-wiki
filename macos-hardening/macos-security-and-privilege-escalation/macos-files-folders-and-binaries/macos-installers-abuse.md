# Nadużycia instalatorów macOS

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Podstawowe informacje o plikach Pkg

Plik **pakietu instalacyjnego macOS** (znany również jako plik `.pkg`) to format pliku używany przez macOS do **dystrybucji oprogramowania**. Te pliki są jak **pudełko zawierające wszystko, czego potrzebuje** kawałek oprogramowania do poprawnej instalacji i uruchomienia.

Sam plik pakietu to archiwum, które przechowuje **hierarchię plików i katalogów, które zostaną zainstalowane na docelowym** komputerze. Może również zawierać **skrypty** do wykonywania zadań przed i po instalacji, takie jak konfigurowanie plików konfiguracyjnych lub czyszczenie starych wersji oprogramowania.

### Hierarchia

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Dystrybucja (xml)**: Dostosowania (tytuł, tekst powitalny...) oraz skrypty/sprawdzenia instalacji
* **PackageInfo (xml)**: Informacje, wymagania instalacji, lokalizacja instalacji, ścieżki do skryptów do uruchomienia
* **Spis materiałów (bom)**: Lista plików do zainstalowania, aktualizacji lub usunięcia wraz z uprawnieniami do plików
* **Zasób (archiwum CPIO gzip)**: Pliki do zainstalowania w `install-location` z PackageInfo
* **Skrypty (archiwum CPIO gzip)**: Skrypty przed i po instalacji oraz więcej zasobów wypakowanych do tymczasowego katalogu do wykonania.

### Dekompresja
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

Pliki DMG, czyli Obrazy Dysków Apple, to format plików używany przez macOS firmy Apple do obrazów dysków. Plik DMG to w zasadzie **montowalny obraz dysku** (zawiera własny system plików), który zawiera surowe dane blokowe, zazwyczaj skompresowane i czasami zaszyfrowane. Gdy otworzysz plik DMG, macOS **montuje go jakby był fizycznym dyskiem**, pozwalając na dostęp do jego zawartości.

{% hint style="danger" %}
Zauważ, że instalatory **`.dmg`** obsługują **tak wiele formatów**, że w przeszłości niektóre z nich zawierające podatności były wykorzystywane do uzyskania **wykonania kodu jądra**.
{% endhint %}

### Hierarchia

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Hierarchia pliku DMG może być różna w zależności od zawartości. Jednakże, dla aplikacji DMG, zazwyczaj podąża ona za tą strukturą:

- Poziom Główny: To jest korzeń obrazu dysku. Zazwyczaj zawiera aplikację i ewentualnie odnośnik do folderu Aplikacje.
- Aplikacja (.app): To jest właściwa aplikacja. W macOS, aplikacja zazwyczaj jest pakietem zawierającym wiele indywidualnych plików i folderów, które tworzą aplikację.
- Odnośnik do Aplikacji: To jest skrót do folderu Aplikacje w macOS. Ma to na celu ułatwienie instalacji aplikacji. Możesz przeciągnąć plik .app do tego skrótu, aby zainstalować aplikację.

## Eskalacja uprawnień poprzez nadużycie pakietów pkg

### Wykonywanie z publicznych katalogów

Jeśli skrypt instalacyjny przed lub po instalacji wykonuje się na przykład z **`/var/tmp/Installerutil`**, a atakujący może kontrolować ten skrypt, to może eskalować uprawnienia za każdym razem, gdy zostanie wykonany. Lub inny podobny przykład:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

To jest [publiczna funkcja](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), którą kilka instalatorów i aktualizatorów wywoła do **wykonania czegoś jako root**. Ta funkcja przyjmuje **ścieżkę** do **pliku**, który ma być **wykonany** jako parametr, jednakże, jeśli atakujący mógłby **zmodyfikować** ten plik, będzie mógł **nadużyć** jego wykonania jako root do **eskalacji uprawnień**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### Wykonanie poprzez montowanie

Jeśli instalator zapisuje do `/tmp/fixedname/bla/bla`, można **utworzyć montowanie** nad `/tmp/fixedname` bez właścicieli, dzięki czemu można **modyfikować dowolny plik podczas instalacji**, aby nadużyć procesu instalacji.

Przykładem tego jest **CVE-2021-26089**, który zdołał **nadpisać skrypt okresowy**, aby uzyskać wykonanie jako root. Aby uzyskać więcej informacji, zapoznaj się z prezentacją: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg jako złośliwe oprogramowanie

### Pusta ładunek

Możliwe jest po prostu wygenerowanie pliku **`.pkg`** z **skryptami przed i po instalacji** bez żadnego ładunku.

### JS w pliku Distribution xml

Możliwe jest dodanie tagów **`<script>`** w pliku **distribution xml** pakietu, a ten kod zostanie wykonany i może **wykonywać polecenia** za pomocą **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

## Odnośniki

* [**DEF CON 27 - Rozpakowywanie Pkg: Spojrzenie wewnątrz pakietów instalacyjnych Macos i powszechne błędy związane z bezpieczeństwem**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "Dziki świat instalatorów macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Rozpakowywanie Pkg: Spojrzenie wewnątrz pakietów instalacyjnych MacOS**](https://www.youtube.com/watch?v=kCXhIYtODBg)
