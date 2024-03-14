# Zmienne środowiskowe w systemie Linux

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Zmienne globalne

Zmienne globalne **będą** dziedziczone przez **procesy potomne**.

Możesz utworzyć zmienną globalną dla bieżącej sesji, wykonując:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ta zmienna będzie dostępna w bieżących sesjach i procesach potomnych.

Możesz **usunąć** zmienną wykonując:
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
## Wyświetlanie bieżących zmiennych
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Wspólne zmienne

Z: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – wyświetlacz używany przez **X**. Zmienna ta zazwyczaj jest ustawiona na **:0.0**, co oznacza pierwszy wyświetlacz na bieżącym komputerze.
* **EDITOR** – preferowany edytor tekstu użytkownika.
* **HISTFILESIZE** – maksymalna liczba linii zawartych w pliku historii.
* **HISTSIZE** – Liczba linii dodawanych do pliku historii po zakończeniu sesji użytkownika.
* **HOME** – katalog domowy.
* **HOSTNAME** – nazwa hosta komputera.
* **LANG** – bieżący język.
* **MAIL** – lokalizacja skrzynki pocztowej użytkownika. Zazwyczaj **/var/spool/mail/USER**.
* **MANPATH** – lista katalogów do wyszukiwania stron podręcznika.
* **OSTYPE** – typ systemu operacyjnego.
* **PS1** – domyślny znak zachęty w bashu.
* **PATH** – przechowuje ścieżkę do wszystkich katalogów zawierających pliki binarne, które chcesz wykonać, podając tylko nazwę pliku, a nie ścieżkę względną lub bezwzględną.
* **PWD** – bieżący katalog roboczy.
* **SHELL** – ścieżka do bieżącego powłoki poleceń (na przykład **/bin/bash**).
* **TERM** – bieżący typ terminala (na przykład **xterm**).
* **TZ** – strefa czasowa.
* **USER** – bieżąca nazwa użytkownika.

## Interesujące zmienne do hakowania

### **HISTFILESIZE**

Zmień **wartość tej zmiennej na 0**, aby po **zakończeniu sesji** plik historii (\~/.bash\_history) **został usunięty**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Zmień **wartość tej zmiennej na 0**, aby po **zakończeniu sesji** żadne polecenie nie było dodane do **pliku historii** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Procesy będą korzystać z zadeklarowanego tutaj **serwera proxy** do połączenia z internetem za pośrednictwem **http lub https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

Procesy będą ufać certyfikatom wskazanym w **tych zmiennych środowiskowych**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Zmień wygląd swojego wiersza poleceń.

[**To jest przykład**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

Zwykły użytkownik:

![](<../.gitbook/assets/image (88).png>)

Jeden, dwa i trzy procesy w tle:

![](<../.gitbook/assets/image (89).png>)

Jeden proces w tle, jeden zatrzymany i ostatnie polecenie nie zakończyło się poprawnie:

![](<../.gitbook/assets/image (90).png>)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
