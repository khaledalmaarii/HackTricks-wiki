# Zmienne środowiskowe Linuxa

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## Zmienne globalne

Zmienne globalne **będą** dziedziczone przez **procesy potomne**.

Możesz utworzyć zmienną globalną dla swojej bieżącej sesji, wykonując:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ta zmienna będzie dostępna w bieżących sesjach i ich procesach potomnych.

Możesz **usunąć** zmienną, wykonując:
```bash
unset MYGLOBAL
```
## Zmienne lokalne

**Zmienne lokalne** mogą być **dostępne** tylko przez **bieżącą powłokę/skrypt**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lista bieżących zmiennych
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – wyświetlacz używany przez **X**. Ta zmienna jest zazwyczaj ustawiona na **:0.0**, co oznacza pierwszy wyświetlacz na bieżącym komputerze.
* **EDITOR** – preferowany edytor tekstu użytkownika.
* **HISTFILESIZE** – maksymalna liczba linii zawartych w pliku historii.
* **HISTSIZE** – liczba linii dodawanych do pliku historii, gdy użytkownik kończy swoją sesję.
* **HOME** – twój katalog domowy.
* **HOSTNAME** – nazwa hosta komputera.
* **LANG** – twój bieżący język.
* **MAIL** – lokalizacja spooling poczty użytkownika. Zazwyczaj **/var/spool/mail/USER**.
* **MANPATH** – lista katalogów do przeszukiwania stron podręcznika.
* **OSTYPE** – typ systemu operacyjnego.
* **PS1** – domyślny prompt w bash.
* **PATH** – przechowuje ścieżkę do wszystkich katalogów, które zawierają pliki binarne, które chcesz wykonać, po prostu podając nazwę pliku, a nie względną lub absolutną ścieżkę.
* **PWD** – bieżący katalog roboczy.
* **SHELL** – ścieżka do bieżącej powłoki poleceń (na przykład **/bin/bash**).
* **TERM** – bieżący typ terminala (na przykład **xterm**).
* **TZ** – twoja strefa czasowa.
* **USER** – twoja bieżąca nazwa użytkownika.

## Interesting variables for hacking

### **HISTFILESIZE**

Zmień **wartość tej zmiennej na 0**, aby po **zakończeniu sesji** **plik historii** (\~/.bash\_history) **został usunięty**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Zmień **wartość tej zmiennej na 0**, aby po **zakończeniu sesji** żadne polecenie nie było dodawane do **pliku historii** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Procesy będą używać zadeklarowanego **proxy** do łączenia się z internetem przez **http lub https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Procesy będą ufać certyfikatom wskazanym w **tych zmiennych środowiskowych**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Zmień wygląd swojego prompta.

[**To jest przykład**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Zwykły użytkownik:

![](<../.gitbook/assets/image (740).png>)

Jedna, dwie i trzy zadania w tle:

![](<../.gitbook/assets/image (145).png>)

Jedno zadanie w tle, jedno zatrzymane, a ostatnia komenda nie zakończyła się poprawnie:

![](<../.gitbook/assets/image (715).png>)


{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
