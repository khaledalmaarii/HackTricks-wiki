# Ataki Fizyczne

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## Odzyskiwanie Hasła BIOS i Bezpieczeństwo Systemu

**Resetowanie BIOS-u** można osiągnąć na kilka sposobów. Większość płyt głównych zawiera **baterię**, która, gdy zostanie usunięta na około **30 minut**, zresetuje ustawienia BIOS-u, w tym hasło. Alternatywnie, można dostosować **jumper na płycie głównej**, aby zresetować te ustawienia, łącząc określone piny.

W sytuacjach, gdy dostosowania sprzętowe nie są możliwe lub praktyczne, **narzędzia programowe** oferują rozwiązanie. Uruchomienie systemu z **Live CD/USB** z dystrybucjami takimi jak **Kali Linux** zapewnia dostęp do narzędzi takich jak **_killCmos_** i **_CmosPWD_**, które mogą pomóc w odzyskiwaniu hasła BIOS.

W przypadkach, gdy hasło BIOS jest nieznane, wprowadzenie go błędnie **trzy razy** zazwyczaj skutkuje kodem błędu. Kod ten można wykorzystać na stronach takich jak [https://bios-pw.org](https://bios-pw.org), aby potencjalnie odzyskać użyteczne hasło.

### Bezpieczeństwo UEFI

Dla nowoczesnych systemów używających **UEFI** zamiast tradycyjnego BIOS-u, narzędzie **chipsec** może być wykorzystane do analizy i modyfikacji ustawień UEFI, w tym wyłączenia **Secure Boot**. Można to osiągnąć za pomocą następującego polecenia:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Analiza RAM i Ataki Cold Boot

RAM przechowuje dane przez krótki czas po odcięciu zasilania, zazwyczaj przez **1 do 2 minut**. Ta trwałość może być wydłużona do **10 minut** poprzez zastosowanie zimnych substancji, takich jak azot ciekły. W tym wydłużonym okresie można utworzyć **zrzut pamięci** za pomocą narzędzi takich jak **dd.exe** i **volatility** do analizy.

### Ataki Direct Memory Access (DMA)

**INCEPTION** to narzędzie zaprojektowane do **manipulacji pamięcią fizyczną** przez DMA, kompatybilne z interfejsami takimi jak **FireWire** i **Thunderbolt**. Umożliwia to ominięcie procedur logowania poprzez patchowanie pamięci, aby akceptowała dowolne hasło. Jednak jest nieskuteczne przeciwko systemom **Windows 10**.

### Live CD/USB do Dostępu do Systemu

Zmiana binariów systemowych, takich jak **_sethc.exe_** lub **_Utilman.exe_**, na kopię **_cmd.exe_** może zapewnić dostęp do wiersza poleceń z uprawnieniami systemowymi. Narzędzia takie jak **chntpw** mogą być używane do edytowania pliku **SAM** instalacji Windows, co pozwala na zmianę haseł.

**Kon-Boot** to narzędzie, które ułatwia logowanie do systemów Windows bez znajomości hasła, tymczasowo modyfikując jądro Windows lub UEFI. Więcej informacji można znaleźć na [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Obsługa Funkcji Bezpieczeństwa Windows

#### Skróty do Rozruchu i Odzyskiwania

- **Supr**: Dostęp do ustawień BIOS.
- **F8**: Wejście w tryb odzyskiwania.
- Naciśnięcie **Shift** po banerze Windows może ominąć autologowanie.

#### Złe Urządzenia USB

Urządzenia takie jak **Rubber Ducky** i **Teensyduino** służą jako platformy do tworzenia **złych urządzeń USB**, zdolnych do wykonywania zdefiniowanych ładunków po podłączeniu do docelowego komputera.

#### Kopia Cienia Woluminu

Uprawnienia administratora pozwalają na tworzenie kopii wrażliwych plików, w tym pliku **SAM**, za pomocą PowerShell.

### Ominięcie Szyfrowania BitLocker

Szyfrowanie BitLocker może być potencjalnie ominięte, jeśli **hasło odzyskiwania** zostanie znalezione w pliku zrzutu pamięci (**MEMORY.DMP**). Narzędzia takie jak **Elcomsoft Forensic Disk Decryptor** lub **Passware Kit Forensic** mogą być wykorzystane w tym celu.

### Inżynieria Społeczna dla Dodania Klucza Odzyskiwania

Nowy klucz odzyskiwania BitLocker może być dodany za pomocą taktyk inżynierii społecznej, przekonując użytkownika do wykonania polecenia, które dodaje nowy klucz odzyskiwania składający się z zer, co upraszcza proces deszyfrowania.

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
