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

## Integralność oprogramowania układowego

**Niestandardowe oprogramowanie układowe i/lub skompilowane pliki binarne mogą być przesyłane w celu wykorzystania luk w integralności lub weryfikacji podpisu**. Można wykonać następujące kroki w celu skompilowania backdoora z bind shell:

1. Oprogramowanie układowe można wyodrębnić za pomocą firmware-mod-kit (FMK).
2. Należy zidentyfikować architekturę oprogramowania układowego i endianness.
3. Można zbudować kompilator krzyżowy za pomocą Buildroot lub innych odpowiednich metod dla środowiska.
4. Backdoor można zbudować za pomocą kompilatora krzyżowego.
5. Backdoor można skopiować do katalogu /usr/bin wyodrębnionego oprogramowania układowego.
6. Odpowiedni plik binarny QEMU można skopiować do rootfs wyodrębnionego oprogramowania układowego.
7. Backdoor można emulować za pomocą chroot i QEMU.
8. Backdoor można uzyskać za pomocą netcat.
9. Plik binarny QEMU należy usunąć z rootfs wyodrębnionego oprogramowania układowego.
10. Zmodyfikowane oprogramowanie układowe można spakować ponownie za pomocą FMK.
11. Oprogramowanie układowe z backdoorem można przetestować, emulując je za pomocą zestawu narzędzi do analizy oprogramowania układowego (FAT) i łącząc się z docelowym adresem IP i portem backdoora za pomocą netcat.

Jeśli już uzyskano dostęp do powłoki root poprzez analizę dynamiczną, manipulację bootloaderem lub testowanie bezpieczeństwa sprzętu, można uruchomić prekompilowane złośliwe pliki binarne, takie jak implanty lub reverse shelle. Zautomatyzowane narzędzia do payloadów/implantów, takie jak framework Metasploit i 'msfvenom', można wykorzystać, wykonując następujące kroki:

1. Należy zidentyfikować architekturę oprogramowania układowego i endianness.
2. Msfvenom można użyć do określenia docelowego payloadu, adresu IP atakującego, numeru portu nasłuchującego, typu pliku, architektury, platformy i pliku wyjściowego.
3. Payload można przesłać do skompromitowanego urządzenia i upewnić się, że ma uprawnienia do wykonania.
4. Metasploit można przygotować do obsługi przychodzących żądań, uruchamiając msfconsole i konfigurując ustawienia zgodnie z payloadem.
5. Reverse shell meterpreter można uruchomić na skompromitowanym urządzeniu.
6. Sesje meterpreter można monitorować w miarę ich otwierania.
7. Można przeprowadzić działania po eksploatacji.

Jeśli to możliwe, można wykorzystać luki w skryptach uruchamiających, aby uzyskać trwały dostęp do urządzenia po ponownych uruchomieniach. Luki te pojawiają się, gdy skrypty uruchamiające odwołują się do, [linkują symbolicznie](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data) lub polegają na kodzie znajdującym się w nieufnych zamontowanych lokalizacjach, takich jak karty SD i wolumeny flash używane do przechowywania danych poza systemami plików root.

## Referencje
* Aby uzyskać więcej informacji, sprawdź [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

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
