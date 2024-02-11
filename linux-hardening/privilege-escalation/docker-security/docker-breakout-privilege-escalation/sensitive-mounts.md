<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


Ufunuo wa `/proc` na `/sys` bila kujitenga kwa njia sahihi ya majina huleta hatari kubwa za usalama, ikiwa ni pamoja na kuongezeka kwa eneo la shambulio na kufichua habari. Direktori hizi zina faili nyeti ambazo, ikiwa hazijasakinishwa vizuri au zinapatikana na mtumiaji asiyeidhinishwa, zinaweza kusababisha kutoroka kwa kontena, mabadiliko ya mwenyeji, au kutoa habari inayosaidia mashambulizi zaidi. Kwa mfano, kusakinisha kimakosa `-v /proc:/host/proc` kunaweza kuzunguka ulinzi wa AppArmor kutokana na asili yake ya msingi ya njia, kuacha `/host/proc` bila ulinzi.

**Unaweza kupata maelezo zaidi ya kila udhaifu unaowezekana katika [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts).**

# Udhaifu wa procfs

## `/proc/sys`
Hii ni direktori inayoruhusu upatikanaji wa kubadilisha pembejeo za kernel, kawaida kupitia `sysctl(2)`, na ina vijaraka kadhaa vya wasiwasi:

### **`/proc/sys/kernel/core_pattern`**
- Iliyoelezwa katika [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Inaruhusu kufafanua programu ya kutekeleza wakati wa kuzalisha faili ya msingi na herufi 128 za kwanza kama hoja. Hii inaweza kusababisha utekelezaji wa nambari ikiwa faili inaanza na mrija `|`.
- **Jaribio la Kujaribu na Kudukua**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Ndiyo # Jaribu upatikanaji wa kuandika
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Weka kiongozi cha desturi
sleep 5 && ./crash & # Chokoza kiongozi
```

### **`/proc/sys/kernel/modprobe`**
- Iliyoelezwa kwa undani katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Ina njia ya mzigo wa moduli ya kernel, inayoitwa kwa kusakinisha moduli za kernel.
- **Mfano wa Kupima Upatikanaji**:
```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Angalia upatikanaji wa modprobe
```

### **`/proc/sys/vm/panic_on_oom`**
- Inahusishwa katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Bendera ya ulimwengu inayodhibiti ikiwa kernel inapata hofu au inaita OOM killer wakati hali ya OOM inatokea.

### **`/proc/sys/fs`**
- Kulingana na [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), ina chaguo na habari kuhusu mfumo wa faili.
- Upatikanaji wa kuandika unaweza kuwezesha mashambulio mbalimbali ya kukataa huduma dhidi ya mwenyeji.

### **`/proc/sys/fs/binfmt_misc`**
- Inaruhusu usajili wa watekelezaji kwa muundo wa binary usio wa asili kulingana na nambari yao ya uchawi.
- Inaweza kusababisha ongezeko la mamlaka au ufikiaji wa kabati wa mizizi ikiwa `/proc/sys/fs/binfmt_misc/register` inaweza kuandikwa.
- Shambulio na maelezo yanayofaa:
- [Rootkit ya maskini kupitia binfmt_misc](https://github.com/toffan/binfmt_misc)
- Mafunzo ya kina: [Kiungo cha Video](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## Wengine katika `/proc`

### **`/proc/config.gz`**
- Inaweza kufichua usanidi wa kernel ikiwa `CONFIG_IKCONFIG_PROC` imezimishwa.
- Inafaa kwa wadukuzi kutambua udhaifu katika kernel inayotumika.

### **`/proc/sysrq-trigger`**
- Inaruhusu kuita amri za Sysrq, zinazoweza kusababisha kuanza upya mara moja au hatua muhimu zingine.
- **Mfano wa Kuanza upya kwa Mwenyeji**:
```bash
echo b > /proc/sysrq-trigger # Inaanza upya mwenyeji
```

### **`/proc/kmsg`**
- Inafichua ujumbe wa mzunguko wa pete wa kernel.
- Inaweza kusaidia katika kudukua kernel, kuvuja kwa anwani, na kutoa habari nyeti ya mfumo.

### **`/proc/kallsyms`**
- Inaorodhesha alama zilizosafirishwa za kernel na anwani zao.
- Muhimu kwa maendeleo ya kudukua kernel, haswa kwa kushinda KASLR.
- Habari ya anwani imezuiliwa na `kptr_restrict` imewekwa kuwa `1` au `2`.
- Maelezo katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/[pid]/mem`**
- Inashirikiana na kifaa cha kumbukumbu ya kernel `/dev/mem`.
- Historia ya kuwa dhaifu kwa mashambulio ya kuongeza mamlaka.
- Zaidi katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/kcore`**
- Inawakilisha kumbukumbu halisi ya mfumo katika muundo wa msingi wa ELF.
- Kusoma kunaweza kufichua yaliyomo ya kumbukumbu ya mfumo wa mwenyeji na kontena zingine.
- Ukubwa mkubwa wa faili unaweza kusababisha maswala ya kusoma au kufeli kwa programu.
- Matumizi ya kina katika [Kudondosha /proc/kcore mnamo 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

### **`/proc/kmem`**
- Kiolesura mbadala kwa `/dev/kmem`, kinawakilisha kumbukumbu halisi ya kernel.
- Inaruhusu kusoma na kuandika, hivyo kubadilisha moja kwa moja kumbukumbu ya kernel.

### **`/proc/mem`**
- Kiolesura mbadala kwa `/dev/mem`, kinawakilisha kumbukumbu halisi.
- Inaruhusu kusoma na kuandika, mabadiliko ya kumbukumbu yote yanahitaji kutatua anwani za kawaida kuwa za kimwili.

### **`/proc/sched_debug`**
- Inarudisha habari ya ratiba ya mchakato, ikipuuza ulinzi wa nafasi ya PID.
- Inafichua majina ya mchakato, kitambul
### **`/sys/class/thermal`**
- Inadhibisha mipangilio ya joto, inaweza kusababisha mashambulizi ya DoS au uharibifu wa kimwili.

### **`/sys/kernel/vmcoreinfo`**
- Inavuja anwani za kernel, inaweza kuhatarisha KASLR.

### **`/sys/kernel/security`**
- Ina `securityfs` interface, inaruhusu usanidi wa Moduli za Usalama za Linux kama AppArmor.
- Upatikanaji unaweza kuwezesha kontena kuzima mfumo wake wa MAC.

### **`/sys/firmware/efi/vars` na `/sys/firmware/efi/efivars`**
- Inafunua interfaces za kuingiliana na pembejeo za EFI katika NVRAM.
- Usanidi mbaya au udanganyifu unaweza kusababisha kompyuta ndogo zilizoharibika au mashine za mwenyeji zisizoweza kuanza.

### **`/sys/kernel/debug`**
- `debugfs` inatoa interface ya kurekebisha bila sheria kwa kernel.
- Historia ya masuala ya usalama kutokana na asili yake isiyo na kizuizi.

## Marejeo
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
