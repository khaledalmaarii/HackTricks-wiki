# Fizyczne Ataki

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana **dark-web**, która oferuje **darmowe** funkcjonalności do sprawdzenia, czy firma lub jej klienci zostali **skompromentowani** przez **złośliwe oprogramowanie kradnące**.

Głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz sprawdzić ich stronę internetową i wypróbować ich silnik za **darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

---

## Odzyskiwanie hasła BIOS i bezpieczeństwo systemu

**Resetowanie BIOS-u** można osiągnąć na kilka sposobów. Większość płyt głównych zawiera **baterię**, która, gdy zostanie usunięta na około **30 minut**, zresetuje ustawienia BIOS-u, w tym hasło. Alternatywnie, można dostosować **jumper na płycie głównej**, aby zresetować te ustawienia, łącząc określone piny.

W sytuacjach, gdy dostosowania sprzętowe nie są możliwe lub praktyczne, **narzędzia programowe** oferują rozwiązanie. Uruchomienie systemu z **Live CD/USB** z dystrybucjami takimi jak **Kali Linux** zapewnia dostęp do narzędzi takich jak **_killCmos_** i **_CmosPWD_**, które mogą pomóc w odzyskiwaniu hasła BIOS.

W przypadkach, gdy hasło BIOS jest nieznane, wprowadzenie go błędnie **trzy razy** zazwyczaj skutkuje kodem błędu. Ten kod można wykorzystać na stronach takich jak [https://bios-pw.org](https://bios-pw.org), aby potencjalnie odzyskać użyteczne hasło.

### Bezpieczeństwo UEFI

Dla nowoczesnych systemów używających **UEFI** zamiast tradycyjnego BIOS-u, narzędzie **chipsec** może być wykorzystane do analizy i modyfikacji ustawień UEFI, w tym wyłączania **Secure Boot**. Można to osiągnąć za pomocą następującego polecenia:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Analiza RAM i ataki zimnego uruchomienia

RAM przechowuje dane krótko po odcięciu zasilania, zazwyczaj przez **1 do 2 minut**. Ta trwałość może być wydłużona do **10 minut** poprzez zastosowanie zimnych substancji, takich jak ciekły azot. W tym wydłużonym okresie można utworzyć **zrzut pamięci** za pomocą narzędzi takich jak **dd.exe** i **volatility** do analizy.

### Ataki Direct Memory Access (DMA)

**INCEPTION** to narzędzie zaprojektowane do **manipulacji pamięcią fizyczną** przez DMA, kompatybilne z interfejsami takimi jak **FireWire** i **Thunderbolt**. Umożliwia to ominięcie procedur logowania poprzez patchowanie pamięci, aby akceptowała dowolne hasło. Jednak jest nieskuteczne przeciwko systemom **Windows 10**.

### Live CD/USB do uzyskania dostępu do systemu

Zmiana binariów systemowych, takich jak **_sethc.exe_** lub **_Utilman.exe_**, na kopię **_cmd.exe_** może zapewnić dostęp do wiersza poleceń z uprawnieniami systemowymi. Narzędzia takie jak **chntpw** mogą być używane do edytowania pliku **SAM** instalacji Windows, co pozwala na zmianę hasła.

**Kon-Boot** to narzędzie, które ułatwia logowanie do systemów Windows bez znajomości hasła, tymczasowo modyfikując jądro Windows lub UEFI. Więcej informacji można znaleźć na stronie [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Obsługa funkcji zabezpieczeń Windows

#### Skróty do uruchamiania i odzyskiwania

- **Supr**: Dostęp do ustawień BIOS.
- **F8**: Wejście w tryb odzyskiwania.
- Naciśnięcie **Shift** po banerze Windows może obejść autologowanie.

#### ZŁE urządzenia USB

Urządzenia takie jak **Rubber Ducky** i **Teensyduino** służą jako platformy do tworzenia **złych urządzeń USB**, zdolnych do wykonywania zdefiniowanych ładunków po podłączeniu do docelowego komputera.

#### Kopia zapasowa woluminu

Uprawnienia administratora pozwalają na tworzenie kopii wrażliwych plików, w tym pliku **SAM**, za pomocą PowerShell.

### Ominięcie szyfrowania BitLocker

Szyfrowanie BitLocker można potencjalnie obejść, jeśli **hasło odzyskiwania** zostanie znalezione w pliku zrzutu pamięci (**MEMORY.DMP**). Narzędzia takie jak **Elcomsoft Forensic Disk Decryptor** lub **Passware Kit Forensic** mogą być wykorzystane w tym celu.

### Inżynieria społeczna w celu dodania klucza odzyskiwania

Nowy klucz odzyskiwania BitLocker można dodać za pomocą taktyk inżynierii społecznej, przekonując użytkownika do wykonania polecenia, które dodaje nowy klucz odzyskiwania składający się z zer, co upraszcza proces deszyfrowania.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana **dark-web**, która oferuje **darmowe** funkcjonalności do sprawdzenia, czy firma lub jej klienci zostali **skompromentowani** przez **złośliwe oprogramowanie kradnące**.

Głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz sprawdzić ich stronę internetową i wypróbować ich silnik za **darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
