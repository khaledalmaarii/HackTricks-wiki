# Ataki fizyczne

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>

## Odzyskiwanie hasła BIOS i zabezpieczenia systemu

**Resetowanie BIOS-u** można osiągnąć na kilka sposobów. Większość płyt głównych zawiera **baterię**, która po usunięciu na około **30 minut** zresetuje ustawienia BIOS-u, w tym hasło. Alternatywnie, można dostosować **zworkę na płycie głównej**, aby zresetować te ustawienia, łącząc konkretne piny.

W sytuacjach, gdy nie można dokonać zmian w sprzęcie lub nie jest to praktyczne, **narzędzia oprogramowania** oferują rozwiązanie. Uruchomienie systemu z **Live CD/USB** z dystrybucjami takimi jak **Kali Linux** umożliwia dostęp do narzędzi takich jak **_killCmos_** i **_CmosPWD_**, które mogą pomóc w odzyskiwaniu hasła BIOS-u.

W przypadkach, gdy hasło BIOS-u jest nieznane, wprowadzenie go nieprawidłowo **trzy razy** zazwyczaj skutkuje kodem błędu. Ten kod można użyć na stronach internetowych takich jak [https://bios-pw.org](https://bios-pw.org), aby potencjalnie odzyskać użyteczne hasło.

### Bezpieczeństwo UEFI

Dla nowoczesnych systemów korzystających z **UEFI** zamiast tradycyjnego BIOS-u, narzędzie **chipsec** może być wykorzystane do analizy i modyfikacji ustawień UEFI, w tym wyłączenia **Secure Boot**. Można to osiągnąć za pomocą następującej komendy:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Analiza RAM i ataki Cold Boot

RAM przechowuje dane krótko po odcięciu zasilania, zazwyczaj przez **1 do 2 minut**. Ta trwałość może być przedłużona do **10 minut** poprzez zastosowanie zimnych substancji, takich jak azot ciekły. W tym wydłużonym okresie można utworzyć **dump pamięci** za pomocą narzędzi takich jak **dd.exe** i **volatility** do analizy.

### Ataki DMA (Direct Memory Access)

**INCEPTION** to narzędzie przeznaczone do **manipulacji fizycznej pamięci** za pomocą DMA, kompatybilne z interfejsami takimi jak **FireWire** i **Thunderbolt**. Pozwala na obejście procedur logowania poprzez zmodyfikowanie pamięci w celu akceptacji dowolnego hasła. Jednak jest nieskuteczne w przypadku systemów **Windows 10**.

### Live CD/USB dla dostępu do systemu

Zmiana binarnych plików systemowych takich jak **_sethc.exe_** lub **_Utilman.exe_** na kopię **_cmd.exe_** może zapewnić wiersz polecenia z uprawnieniami systemowymi. Narzędzia takie jak **chntpw** mogą być używane do edycji pliku **SAM** instalacji systemu Windows, umożliwiając zmianę hasła.

**Kon-Boot** to narzędzie ułatwiające logowanie do systemów Windows bez znajomości hasła poprzez tymczasową modyfikację jądra systemu Windows lub UEFI. Więcej informacji można znaleźć na stronie [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Obsługa funkcji zabezpieczeń systemu Windows

#### Skróty do uruchamiania i odzyskiwania

- **Supr**: Uzyskaj dostęp do ustawień BIOS-u.
- **F8**: Wejdź w tryb odzyskiwania.
- Naciśnięcie klawisza **Shift** po banerze systemu Windows może ominąć automatyczne logowanie.

#### Urządzenia BAD USB

Urządzenia takie jak **Rubber Ducky** i **Teensyduino** służą jako platformy do tworzenia **złych urządzeń USB**, zdolnych do wykonania predefiniowanych ładunków po podłączeniu do docelowego komputera.

#### Kopie woluminów cieni

Uprawnienia administratora pozwalają na tworzenie kopii poufnych plików, w tym pliku **SAM**, za pomocą PowerShell.

### Ominiecie szyfrowania BitLocker

Szyfrowanie BitLocker może być potencjalnie obejśc, jeśli **hasło odzyskiwania** zostanie znalezione w pliku dumpu pamięci (**MEMORY.DMP**). Narzędzia takie jak **Elcomsoft Forensic Disk Decryptor** lub **Passware Kit Forensic** mogą być wykorzystane w tym celu.

### Inżynieria społeczna w celu dodania klucza odzyskiwania

Nowy klucz odzyskiwania BitLocker można dodać za pomocą taktyk inżynierii społecznej, przekonując użytkownika do wykonania polecenia dodającego nowy klucz odzyskiwania składający się z zer, upraszczając tym samym proces deszyfrowania.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>
