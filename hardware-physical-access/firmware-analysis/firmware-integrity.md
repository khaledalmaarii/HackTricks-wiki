<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>

## Integralność firmware'u

**Niestandardowe firmware'y i/lub skompilowane pliki binarne mogą być przesłane w celu wykorzystania luk w integralności lub weryfikacji podpisu**. Można zastosować następujące kroki do kompilacji backdooru bind shell:

1. Firmware można wyodrębnić przy użyciu narzędzia firmware-mod-kit (FMK).
2. Należy zidentyfikować architekturę i kolejność bajtów docelowego firmware'u.
3. Można zbudować kompilator krzyżowy przy użyciu Buildroot lub innych odpowiednich metod dla danej środowiska.
4. Backdoor można zbudować przy użyciu kompilatora krzyżowego.
5. Backdoor można skopiować do katalogu /usr/bin wyodrębnionego firmware'u.
6. Odpowiedni plik binarny QEMU można skopiować do korzenia wyodrębnionego firmware'u.
7. Backdoor można emulować przy użyciu chroot i QEMU.
8. Backdoor można uzyskać dostęp za pomocą netcat.
9. Plik binarny QEMU powinien zostać usunięty z korzenia wyodrębnionego firmware'u.
10. Zmodyfikowany firmware można spakować przy użyciu FMK.
11. Backdoored firmware można przetestować, emulując go za pomocą narzędzia do analizy firmware (FAT) i łącząc się z docelowym adresem IP i portem backdooru za pomocą netcat.

Jeśli już uzyskano dostęp do root shell'a poprzez analizę dynamiczną, manipulację bootloaderem lub testy bezpieczeństwa sprzętu, można wykonać złośliwe pliki binarne, takie jak implanty lub odwrócone shelle. Automatyczne narzędzia do generowania payloadów/implantów, takie jak framework Metasploit i 'msfvenom', można wykorzystać, stosując następujące kroki:

1. Należy zidentyfikować architekturę i kolejność bajtów docelowego firmware'u.
2. Msfvenom można użyć do określenia docelowego payloadu, adresu IP hosta atakującego, numeru portu nasłuchiwania, typu pliku, architektury, platformy i pliku wyjściowego.
3. Payload można przesłać do skompromitowanego urządzenia i upewnić się, że ma uprawnienia do wykonania.
4. Metasploit można przygotować do obsługi przychodzących żądań, uruchamiając msfconsole i konfigurując ustawienia zgodnie z payloadem.
5. Odwrócony shell meterpreter można uruchomić na skompromitowanym urządzeniu.
6. Sesje meterpretera można monitorować w miarę ich otwierania się.
7. Można wykonywać działania po eksploatacji.

Jeśli to możliwe, można wykorzystać podatności w skryptach startowych, aby uzyskać trwały dostęp do urządzenia po ponownym uruchomieniu. Takie podatności pojawiają się, gdy skrypty startowe odwołują się do kodu znajdującego się w niezaufanych zamontowanych lokalizacjach, takich jak karty SD i woluminy flash używane do przechowywania danych poza systemem plików root.

## Odnośniki
* Aby uzyskać więcej informacji, sprawdź [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>
