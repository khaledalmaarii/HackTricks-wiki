# Misbruik van Docker Socket vir Voorregverhoging

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

Daar is soms geleenthede waar jy net **toegang het tot die Docker-socket** en dit wil gebruik om **voorregte te verhoog**. Sommige aksies kan baie verdag wees en jy wil dit dalk vermy, so hier kan jy verskillende vlae vind wat nuttig kan wees om voorregte te verhoog:

### Via berging

Jy kan verskillende dele van die **lêersisteem** in 'n houer wat as root loop **berg** en **toegang** daartoe verkry.\
Jy kan ook **misbruik maak van 'n berging om voorregte te verhoog** binne die houer.

* **`-v /:/host`** -> Berg die gasheer-lêersisteem in die houer sodat jy die gasheer-lêersisteem kan **lees**.
* As jy wil **voel asof jy op die gasheer is**, maar in die houer is, kan jy ander verdedigingsmeganismes deaktiveer deur vlae soos die volgende te gebruik:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Dit is soortgelyk aan die vorige metode, maar hier **berg ons die toesteldisk**. Voer dan binne die houer `mount /dev/sda1 /mnt` uit en jy kan toegang verkry tot die **gasheer-lêersisteem** in `/mnt`
* Voer `fdisk -l` in die gasheer uit om die `</dev/sda1>`-toestel te vind om te berg
* **`-v /tmp:/host`** -> As jy om een ​​of ander rede net 'n sekere gids van die gasheer kan berg en jy toegang het binne die gasheer. Berg dit en skep 'n **`/bin/bash`** met **suid** in die gebergde gids sodat jy dit van die gasheer kan **uitvoer en na root kan verhoog**.

{% hint style="info" %}
Let daarop dat jy dalk nie die gids `/tmp` kan berg nie, maar jy kan 'n **verskillende skryfbare gids** berg. Jy kan skryfbare gidsies vind deur die volgende te gebruik: `find / -writable -type d 2>/dev/null`

**Let daarop dat nie al die gidse in 'n Linux-masjien die suid-bit sal ondersteun nie!** Om te bepaal watter gidse die suid-bit ondersteun, voer `mount | grep -v "nosuid"` uit. Byvoorbeeld, gewoonlik ondersteun `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` en `/var/lib/lxcfs` nie die suid-bit nie.

Let ook daarop dat as jy **`/etc`** of enige ander gids **wat konfigurasie-lêers bevat** kan berg, kan jy hulle vanuit die Docker-houer as root verander om hulle in die gasheer te **misbruik en voorregte te verhoog** (dalk deur `/etc/shadow` te wysig)
{% endhint %}

### Ontsnapping uit die houer

* **`--privileged`** -> Met hierdie vlag verwyder jy [alle isolasie uit die houer](docker-privileged.md#what-affects). Kyk na tegnieke om [uit bevoorregte houers as root te ontsnap](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Om [voorregte te verhoog deur gebruik te maak van funksies](../linux-capabilities.md), **verleen daardie funksie aan die houer** en deaktiveer ander beskermingsmetodes wat die uitbuiting kan voorkom.

### Curl

Op hierdie bladsy het ons maniere bespreek om voorregte te verhoog deur gebruik te maak van Docker-vlae, jy kan maniere vind om hierdie metodes te misbruik deur die curl-opdrag op die bladsy te gebruik:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
