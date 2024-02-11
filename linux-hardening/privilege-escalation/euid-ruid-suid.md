# euid, ruid, suid

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? au ungependa kupata ufikiaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

### Vitambulisho vya Utambuzi wa Mtumiaji

- **`ruid`**: Kitambulisho cha mtumiaji halisi kinawakilisha mtumiaji ambaye alianzisha mchakato.
- **`euid`**: Inajulikana kama kitambulisho cha mtumiaji kinachofaa, inawakilisha kitambulisho cha mtumiaji kinachotumiwa na mfumo kuthibitisha mamlaka ya mchakato. Kwa ujumla, `euid` inafanana na `ruid`, isipokuwa katika hali kama utekelezaji wa faili ya SetUID, ambapo `euid` inachukua kitambulisho cha mmiliki wa faili, hivyo kutoa ruhusa maalum za uendeshaji.
- **`suid`**: Kitambulisho hiki cha mtumiaji kilichohifadhiwa ni muhimu wakati mchakato wenye mamlaka ya juu (kawaida unakimbia kama root) unahitaji kwa muda kutoa mamlaka yake ya juu ili kutekeleza kazi fulani, kisha baadaye kurudisha hadhi yake ya awali iliyoinuliwa.

#### Taarifa muhimu
Mchakato usiofanya kazi chini ya root unaweza kubadilisha tu `euid` yake ili ifanane na `ruid`, `euid`, au `suid` ya sasa.

### Kuelewa Kazi za set*uid

- **`setuid`**: Kinyume na dhana za awali, `setuid` kimsingi hubadilisha `euid` badala ya `ruid`. Hasa, kwa michakato yenye mamlaka, inalinganisha `ruid`, `euid`, na `suid` na mtumiaji aliyetajwa, mara nyingi root, kwa ufanisi kufanya vitambulisho hivi kuwa thabiti kutokana na `suid` inayobadilisha. Maelezo zaidi yanaweza kupatikana kwenye [ukurasa wa man wa setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** na **`setresuid`**: Hizi ni kazi zinazoruhusu marekebisho ya kina ya `ruid`, `euid`, na `suid`. Walakini, uwezo wao unategemea kiwango cha mamlaka ya mchakato. Kwa michakato isiyokuwa ya root, marekebisho yanazuiliwa kwa thamani za sasa za `ruid`, `euid`, na `suid`. Kwa upande mwingine, michakato ya root au ile yenye uwezo wa `CAP_SETUID` inaweza kutoa thamani za kiholela kwa vitambulisho hivi. Taarifa zaidi inaweza kupatikana kwenye [ukurasa wa man wa setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) na [ukurasa wa man wa setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Hizi ni huduma zilizoundwa sio kama kifaa cha usalama lakini kusaidia mchakato wa uendeshaji uliokusudiwa, kama wakati programu inachukua kitambulisho cha mtumiaji mwingine kwa kubadilisha kitambulisho chake cha mtumiaji kinachofaa.

Ni muhimu kutambua kwamba wakati `setuid` inaweza kuwa chaguo la kawaida kwa kuinua mamlaka hadi root (kwa kuwa inalinganisha vitambulisho vyote na root), kutofautisha kati ya huduma hizi ni muhimu kwa kuelewa na kudhibiti tabia za vitambulisho vya mtumiaji katika hali tofauti.

### Mbinu za Utekelezaji wa Programu katika Linux

#### **Wito wa Mfumo wa `execve`**
- **Uwezo**: `execve` inaanzisha programu, iliyopangwa na hoja ya kwanza. Inachukua hoja mbili za safu, `argv` kwa hoja na `envp` kwa mazingira.
- **Tabia**: Inahifadhi nafasi ya kumbukumbu ya mwito lakini inasasisha safu ya steki, rundo, na data. Kanuni ya programu inabadilishwa na programu mpya.
- **Uhifadhi wa Kitambulisho cha Mtumiaji**:
- `ruid`, `euid`, na vitambulisho vya kikundi vya ziada vinabaki bila kubadilika.
- `euid` inaweza kuwa na mabadiliko madogo ikiwa programu mpya ina biti ya SetUID iliyowekwa.
- `suid` inasasishwa kutoka `euid` baada ya utekelezaji.
- **Nyaraka**: Maelezo ya kina yanaweza kupatikana kwenye [ukurasa wa man wa `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **Kazi ya `system`**
- **Uwezo**: Tofauti na `execve`, `system` inaunda mchakato wa watoto kwa kutumia `fork` na inatekeleza amri ndani ya mchakato huo wa watoto kwa kutumia `execl`.
- **Utekelezaji wa Amri**: Inatekeleza amri kupitia `sh` na `execl("/bin/sh", "sh", "-c", amri, (char *) NULL);`.
- **Tabia**: Kwa kuwa `execl` ni aina ya `execve`, inafanya kazi kwa njia sawa lakini katika muktadha wa mchakato mpya wa watoto.
- **Nyaraka**: Maelezo zaidi yanaweza kupatikana kwenye [ukurasa wa man wa `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Tabia ya `bash` na `sh` na SUID**
- **`bash`**:
- Ina chaguo la `-p` linaloathiri jinsi `euid` na `ruid` zinavyoshughulikiwa.
- Bila `-p`, `bash` inaweka `euid` kuwa `ruid` ikiwa awali zinatofautiana.
- Na `-p`, `euid` ya awali inahifadhiwa.
- Maelezo zaidi yanaweza kupatikana kwenye [ukurasa wa man wa `bash`](https://linux.die.net/man/1/bash).
- **`sh`**:
- Haina mfumo kama `-p` katika `bash`.
- Tabia inayohusiana na vitambulisho vya mtumiaji haijatajwa wazi, isipokuwa chini ya chaguo la `-i`, ikisisitiza uhifadhi wa usawa wa `euid` na `ruid`.
- Taarifa zaidi inapatikana kwenye [ukurasa wa man wa `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Mbinu hizi, tofauti katika uendeshaji wao, zinatoa mbalimbali ya chaguzi za kutekeleza na kubadilisha kati ya programu, na nuances maalum katika jinsi vitambulisho vya mtumiaji vinavyosimamiwa na kuhifadhiwa.

### Kujaribu Tabia za Vitambulisho vya Mtumiaji katika Utekelezaji

Mifano imechukuliwa kutoka https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, angalia kwa maelezo zaidi

#### Kesi
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Ukuzaji na Ruhusa:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

* `ruid` na `euid` huanza kama 99 (hakuna mtu) na 1000 (frank) mtawalia.
* `setuid` inaweka wote kuwa 1000.
* `system` inatekeleza `/bin/bash -c id` kutokana na symlink kutoka sh kwenda bash.
* `bash`, bila `-p`, inabadilisha `euid` ili kulingana na `ruid`, hivyo wote wawili kuwa 99 (hakuna mtu).

#### Kesi 2: Kutumia setreuid na system

**Msimbo wa C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Ukuzaji na Ruhusa:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

* `setreuid` inaweka ruid na euid kuwa 1000.
* `system` inaita bash, ambayo inadumisha vitambulisho vya mtumiaji kutokana na usawa wao, na kwa hiyo inafanya kazi kama frank.

#### Kesi ya 3: Kutumia setuid na execve
Lengo: Kuchunguza mwingiliano kati ya setuid na execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

* `ruid` inabaki kuwa 99, lakini euid imewekwa kuwa 1000, kulingana na athari ya setuid.

**Mfano wa Msimbo wa C 2 (Kuita Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

* Ingawa `euid` imewekwa kuwa 1000 na `setuid`, `bash` inarejesha euid kuwa `ruid` (99) kutokana na kutokuwepo kwa `-p`.

**Mfano wa Kanuni ya C 3 (Kutumia bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Marejeo
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye repo ya [hacktricks](https://github.com/carlospolop/hacktricks) na [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
