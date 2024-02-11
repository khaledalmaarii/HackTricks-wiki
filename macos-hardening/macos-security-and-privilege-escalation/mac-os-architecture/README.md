# macOS Kernel i Rozszerzenia Systemowe

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Jądro XNU

**Rdzeniem macOS jest XNU**, co oznacza "X is Not Unix". To jądro składa się z **mikrojądra Mach** (o którym będzie mowa później), **oraz** elementów pochodzących z dystrybucji Berkeley Software Distribution (**BSD**). XNU zapewnia również platformę dla **sterowników jądra za pomocą systemu o nazwie I/O Kit**. Jądro XNU jest częścią projektu open source Darwin, co oznacza, że **jego kod źródłowy jest dostępny bezpłatnie**.

Z perspektywy badacza bezpieczeństwa lub programisty Unix, **macOS** może wydawać się dość **podobne** do systemu **FreeBSD** z eleganckim interfejsem graficznym i wieloma niestandardowymi aplikacjami. Większość aplikacji opracowanych dla BSD będzie kompilować i działać na macOS bez konieczności wprowadzania zmian, ponieważ narzędzia wiersza poleceń znane użytkownikom Unix są wszystkie dostępne w macOS. Jednak ze względu na to, że jądro XNU zawiera Mach, istnieją pewne istotne różnice między tradycyjnym systemem Unix-podobnym a macOS, a te różnice mogą powodować potencjalne problemy lub dostarczać unikalne korzyści.

Wersja open source XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach to **mikrojądro** zaprojektowane do **kompatybilności z UNIX**. Jednym z jego kluczowych założeń projektowych było **minimalizowanie** ilości **kodu** działającego w przestrzeni **jądra** i zamiast tego umożliwienie wielu typowych funkcji jądra, takich jak system plików, sieciowanie i wejście/wyjście, **działanie jako zadania na poziomie użytkownika**.

W XNU, Mach jest **odpowiedzialny za wiele z krytycznych operacji na niskim poziomie**, które typowo obsługuje jądro, takie jak planowanie procesora, wielozadaniowość i zarządzanie pamięcią wirtualną.

### BSD

Jądro XNU **również zawiera** znaczną ilość kodu pochodzącego z projektu **FreeBSD**. Ten kod **działa jako część jądra wraz z Machem**, w tej samej przestrzeni adresowej. Jednak kod FreeBSD w XNU może różnić się znacznie od oryginalnego kodu FreeBSD, ponieważ konieczne były modyfikacje, aby zapewnić jego kompatybilność z Mach. FreeBSD przyczynia się do wielu operacji jądra, w tym:

* Zarządzanie procesami
* Obsługa sygnałów
* Podstawowe mechanizmy bezpieczeństwa, w tym zarządzanie użytkownikami i grupami
* Infrastruktura wywołań systemowych
* Stos TCP/IP i gniazdka
* Zapora i filtrowanie pakietów

Zrozumienie interakcji między BSD a Mach może być skomplikowane ze względu na różne ramy konceptualne. Na przykład, BSD używa procesów jako swojej podstawowej jednostki wykonawczej, podczas gdy Mach działa na podstawie wątków. Ta niezgodność jest pogodzona w XNU poprzez **powiązanie każdego procesu BSD z zadaniem Mach**, które zawiera dokładnie jeden wątek Mach. Gdy używane jest wywołanie systemowe fork() BSD, kod BSD w jądrze używa funkcji Macha do utworzenia struktury zadania i wątku.

Ponadto, **Mach i BSD utrzymują różne modele bezpieczeństwa**: **model bezpieczeństwa Macha** opiera się na **prawach portów**, podczas gdy **model bezpieczeństwa BSD** działa na podstawie **własności procesu**. Różnice między tymi dwoma modelami czasami prowadzą do podatności na eskalację uprawnień lokalnych. Oprócz typowych wywołań systemowych, istnieją również **pułapki Macha, które pozwalają programom przestrzeni użytkownika na interakcję z jądrem**. Te różne elementy razem tworzą wieloaspektową, hybrydową architekturę jądra macOS.

### I/O Kit - Sterowniki

I/O Kit to open-source'owy, obiektowy **framework sterowników urządzeń** w jądrze XNU, obsługujący **dynamicznie ładowane sterowniki urządzeń**. Pozwala na dodawanie modułowego kodu do jądra w locie, obsługując różnorodny sprzęt.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Komunikacja Międzyprocesowa

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

**Kernelcache** to **prekompilowana i połączona wersja jądra XNU**, wraz z niezbędnymi **sterownikami urządzeń** i **rozszerzeniami jądra**. Jest przechowywany w **skompresowanym** formacie i jest dekompresowany do pamięci podczas procesu uruchamiania systemu. Kernelcache umożliwia **szybsze uruchamianie systemu** poprzez posiadanie gotowej do uruchomienia wersji jądra i kluczowych sterowników, co skraca czas i zasoby, które w przeciwnym razie zostałyby wykorzystane na dynamiczne ładowanie i łączenie tych komponentów podczas uruchamiania systemu.

W iOS znajduje się w **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, a w macOS można go znaleźć za pomocą **`find / -name kernelcache 2>/dev/null`**

#### IMG4

Format pliku IMG4 to format kontenera używanego przez Apple w urządzeniach iOS i macOS do bezpiecznego **przechowywania i weryfikowania** komponentów oprogramowania (takich jak **kernelcache**). Format IMG4 zawiera nagłówek i kilka tagów, które zawierają różne części danych, w tym rzeczywiste dane (jak jądro lub bootloader), podpis i zestaw właściwości manifestu. Format obsługuje weryfikację kryptograficzną, umożliwiając urządzeniu potwierdzenie autentyczności i integralności komponentu oprogramowania przed jego wykonaniem.

Zazwyczaj składa się z następujących elementów:

* **Dane (IM4P)**:
* Często skompresowane (LZFSE4, LZSS, ...)
* Opcjonalnie zaszyfrowane
* **Manifest (IM4M)**:
* Zawiera podpis
* Dodatkowy słownik Klucz/Wartość
* **Informacje o przywracaniu (IM4R)**:
* Znane również jako APNonce
* Zapobiega odtwarzaniu niektórych aktualizacji
* OPCJONALNE: Zazwyczaj nie jest to znalezione

Dekompresuj Kernelcache:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Symbole kernelcache

Czasami Apple udostępnia **kernelcache** z **symbolami**. Możesz pobrać niektóre firmware z symbolami, klikając na linki na stronie [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

To są firmware Apple, które można pobrać z [**https://ipsw.me/**](https://ipsw.me/). Oprócz innych plików, zawiera on **kernelcache**.\
Aby **wyodrębnić** pliki, wystarczy je po prostu **rozpakować**.

Po rozpakowaniu firmware otrzymasz plik o nazwie: **`kernelcache.release.iphone14`**. Jest on w formacie **IMG4**, interesujące informacje można wyodrębnić za pomocą:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
Możesz sprawdzić wyodrębniony kernelcache pod kątem symboli za pomocą: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Teraz możemy **wyodrębnić wszystkie rozszerzenia** lub **to, które cię interesuje:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Rozszerzenia jądra macOS

macOS jest **bardzo restrykcyjny w ładowaniu rozszerzeń jądra** (.kext) ze względu na wysokie uprawnienia, z jakimi kod będzie uruchamiany. W rzeczywistości, domyślnie jest to praktycznie niemożliwe (chyba że zostanie znalezione obejście).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Rozszerzenia systemowe macOS

Zamiast używać rozszerzeń jądra, macOS stworzył rozszerzenia systemowe, które oferują interfejsy API na poziomie użytkownika do interakcji z jądrem. W ten sposób programiści mogą uniknąć korzystania z rozszerzeń jądra.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Odwołania

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
