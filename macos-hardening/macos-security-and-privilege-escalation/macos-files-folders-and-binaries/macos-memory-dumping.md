# macOS Memory Dumping

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## Memory Artifacts

### Swap Files

Pliki wymiany, takie jak `/private/var/vm/swapfile0`, służą jako **bufory, gdy pamięć fizyczna jest pełna**. Gdy nie ma już miejsca w pamięci fizycznej, jej dane są przenoszone do pliku wymiany, a następnie przywracane do pamięci fizycznej w razie potrzeby. Może być obecnych wiele plików wymiany, o nazwach takich jak swapfile0, swapfile1 itd.

### Hibernate Image

Plik znajdujący się w `/private/var/vm/sleepimage` jest kluczowy podczas **trybu hibernacji**. **Dane z pamięci są przechowywane w tym pliku, gdy OS X hibernuje**. Po obudzeniu komputera system odzyskuje dane pamięci z tego pliku, co pozwala użytkownikowi kontynuować tam, gdzie przerwał.

Warto zauważyć, że w nowoczesnych systemach MacOS ten plik jest zazwyczaj szyfrowany z powodów bezpieczeństwa, co utrudnia odzyskiwanie.

* Aby sprawdzić, czy szyfrowanie jest włączone dla sleepimage, można uruchomić polecenie `sysctl vm.swapusage`. Pokaże to, czy plik jest szyfrowany.

### Memory Pressure Logs

Innym ważnym plikiem związanym z pamięcią w systemach MacOS jest **dziennik ciśnienia pamięci**. Dzienniki te znajdują się w `/var/log` i zawierają szczegółowe informacje o użyciu pamięci przez system oraz zdarzeniach ciśnienia. Mogą być szczególnie przydatne do diagnozowania problemów związanych z pamięcią lub zrozumienia, jak system zarządza pamięcią w czasie.

## Dumping memory with osxpmem

Aby zrzucić pamięć w maszynie MacOS, można użyć [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Uwaga**: Poniższe instrukcje będą działać tylko na Macach z architekturą Intel. To narzędzie jest teraz archiwizowane, a ostatnia wersja została wydana w 2017 roku. Pobrany binarny plik za pomocą poniższych instrukcji jest skierowany na chipy Intel, ponieważ Apple Silicon nie istniał w 2017 roku. Może być możliwe skompilowanie binarnego pliku dla architektury arm64, ale będziesz musiał spróbować samodzielnie.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Jeśli napotkasz ten błąd: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Możesz to naprawić, wykonując:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Inne błędy** mogą być naprawione przez **zezwolenie na załadowanie kext** w "Bezpieczeństwo i prywatność --> Ogólne", po prostu **zezwól** na to.

Możesz również użyć tego **onelinera**, aby pobrać aplikację, załadować kext i zrzucić pamięć:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}


{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
