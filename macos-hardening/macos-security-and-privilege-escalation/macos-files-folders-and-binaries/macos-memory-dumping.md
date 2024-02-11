# Dumpowanie pamięci w systemie macOS

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Artefakty pamięci

### Pliki wymiany (Swap Files)

Pliki wymiany, takie jak `/private/var/vm/swapfile0`, służą jako **bufory podręczne, gdy pamięć fizyczna jest pełna**. Gdy nie ma już miejsca w pamięci fizycznej, jej dane są przenoszone do pliku wymiany, a następnie przywracane do pamięci fizycznej w miarę potrzeby. Może istnieć wiele plików wymiany o nazwach takich jak swapfile0, swapfile1, itd.

### Obraz hibernacji (Hibernate Image)

Plik znajdujący się pod adresem `/private/var/vm/sleepimage` jest kluczowy podczas **trybu hibernacji**. **Dane z pamięci są przechowywane w tym pliku podczas hibernacji systemu OS X**. Po wybudzeniu komputera system odzyskuje dane z pamięci z tego pliku, umożliwiając użytkownikowi kontynuowanie tam, gdzie skończył.

Warto zauważyć, że w nowoczesnych systemach MacOS ten plik jest zwykle szyfrowany ze względów bezpieczeństwa, co utrudnia jego odzyskanie.

* Aby sprawdzić, czy szyfrowanie jest włączone dla sleepimage, można uruchomić polecenie `sysctl vm.swapusage`. Pokaże to, czy plik jest zaszyfrowany.

### Dzienniki nacisku na pamięć (Memory Pressure Logs)

Innym ważnym plikiem związanym z pamięcią w systemach MacOS są **dzienniki nacisku na pamięć**. Te dzienniki znajdują się w `/var/log` i zawierają szczegółowe informacje na temat wykorzystania pamięci systemu i zdarzeń związanych z naciskiem na pamięć. Mogą być szczególnie przydatne do diagnozowania problemów związanymi z pamięcią lub zrozumienia sposobu zarządzania pamięcią przez system w czasie.

## Dumpowanie pamięci za pomocą osxpmem

Aby zdumpować pamięć w systemie MacOS, można użyć [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Uwaga**: Poniższe instrukcje będą działać tylko dla komputerów Mac z architekturą Intel. Ten narzędzie jest teraz zarchiwizowane, a ostatnie wydanie miało miejsce w 2017 roku. Pobrany binarny plik za pomocą poniższych instrukcji jest przeznaczony dla chipów Intel, ponieważ Apple Silicon nie istniał w 2017 roku. Możliwe jest skompilowanie binarnego pliku dla architektury arm64, ale będziesz musiał to sprawdzić samodzielnie.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Jeśli napotkasz ten błąd: `osxpmem.app/MacPmem.kext nie załadował się - (libkern/kext) błąd uwierzytelniania (właściciel pliku/uprawnienia); sprawdź dzienniki systemowe/jądra w poszukiwaniu błędów lub spróbuj kextutil(8)` Możesz go naprawić wykonując:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Inne błędy** można naprawić, **pozwalając na załadowanie kext** w "Bezpieczeństwo i prywatność --> Ogólne", po prostu **pozwól** na to.

Możesz również użyć tego **onelinera**, aby pobrać aplikację, załadować kext i zrzucić pamięć:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
