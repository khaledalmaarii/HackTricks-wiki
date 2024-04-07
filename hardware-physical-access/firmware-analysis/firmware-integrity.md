<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Integralność oprogramowania układowego

**Niestandardowe oprogramowanie układowe i/lub skompilowane pliki binarne mogą być wgrywane w celu wykorzystania luk w integralności lub weryfikacji podpisu**. Można postępować zgodnie z poniższymi krokami w celu kompilacji backdooru bind shell:

1. Oprogramowanie układowe można wyodrębnić za pomocą zestawu narzędzi do modyfikacji oprogramowania układowego (FMK).
2. Należy zidentyfikować architekturę i kolejność bajtów docelowego oprogramowania układowego.
3. Można zbudować kompilator krzyżowy za pomocą Buildroot lub innych odpowiednich metod dla środowiska.
4. Backdoor można zbudować za pomocą kompilatora krzyżowego.
5. Backdoor można skopiować do wyodrębnionego katalogu /usr/bin oprogramowania układowego.
6. Odpowiedni plik binarny QEMU można skopiować do wyodrębnionego systemu plików oprogramowania układowego.
7. Backdoor można emulować za pomocą chroot i QEMU.
8. Backdoor można uzyskać dostęp za pomocą netcat.
9. Plik binarny QEMU powinien zostać usunięty z systemu plików oprogramowania układowego.
10. Zmodyfikowane oprogramowanie układowe można spakować za pomocą FMK.
11. Oprogramowanie z backdoorem można przetestować, emulując je za pomocą zestawu narzędzi do analizy oprogramowania układowego (FAT) i łącząc się z docelowym adresem IP i portem backdoora za pomocą netcat.

Jeśli już uzyskano dostęp do roota poprzez analizę dynamiczną, manipulację bootloadera lub testowanie bezpieczeństwa sprzętu, można wykonać złośliwe skompilowane pliki binarne, takie jak implanty lub odwrócone shelle. Narzędzia do automatycznego generowania ładunków/implantów, takie jak framework Metasploit i 'msfvenom', można wykorzystać, postępując zgodnie z poniższymi krokami:

1. Należy zidentyfikować architekturę i kolejność bajtów docelowego oprogramowania układowego.
2. Msfvenom można użyć do określenia docelowego ładunku, adresu IP hosta atakującego, numeru portu nasłuchiwania, typu pliku, architektury, platformy i pliku wyjściowego.
3. Ładunek można przesłać do skompromitowanego urządzenia i upewnić się, że ma uprawnienia do wykonania.
4. Metasploit można przygotować do obsługi przychodzących żądań, uruchamiając msfconsole i konfigurując ustawienia zgodnie z ładunkiem.
5. Odwrócony shell meterpreter może zostać uruchomiony na skompromitowanym urządzeniu.
6. Sesje meterpretera mogą być monitorowane podczas ich otwierania.
7. Można wykonać działania post-eksploatacyjne.

Jeśli to możliwe, można wykorzystać podatności w skryptach uruchamiania, aby uzyskać trwały dostęp do urządzenia po ponownym uruchomieniu. Te podatności pojawiają się, gdy skrypty uruchamiania odwołują się, [tworzą dowiązania symboliczne](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data) lub zależą od kodu znajdującego się w niezaufanych zamontowanych lokalizacjach, takich jak karty SD i woluminy flash używane do przechowywania danych poza systemami plików root.

## Referencje
* Aby uzyskać dalsze informacje, sprawdź [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

<details>
