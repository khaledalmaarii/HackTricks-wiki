# CGroups

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

**Linux Control Groups**, au **cgroups**, ni kipengele cha kernel ya Linux kinachoruhusu ugawaji, kikomo, na vipaumbele vya rasilimali za mfumo kama vile CPU, kumbukumbu, na diski I/O kati ya vikundi vya michakato. Hutoa njia ya **kusimamia na kuisolate matumizi ya rasilimali** ya vikundi vya michakato, ambayo ni muhimu kwa madhumuni kama kikomo cha rasilimali, kuisolishwa kwa kazi, na vipaumbele vya rasilimali kati ya vikundi tofauti vya michakato.

Kuna **toleo mbili za cgroups**: toleo 1 na toleo 2. Zote zinaweza kutumiwa kwa pamoja kwenye mfumo. Tofauti kuu ni kwamba **cgroups toleo 2** inaleta **muundo wa kihierarkia kama mti**, kuruhusu ugawaji wa rasilimali wenye undani na maelezo kati ya vikundi vya michakato. Aidha, toleo 2 linakuja na uboreshaji mbalimbali, ikiwa ni pamoja na:

Pamoja na muundo mpya wa kihierarkia, cgroups toleo 2 pia ilileta **mabadiliko na uboreshaji mwingine**, kama vile msaada kwa **wakaguzi wa rasilimali mpya**, msaada bora kwa programu za zamani, na utendaji ulioboreshwa.

Kwa ujumla, cgroups **toleo 2 inatoa huduma zaidi na utendaji bora** kuliko toleo 1, lakini toleo la kwanza linaweza bado kutumiwa katika hali fulani ambapo utangamano na mifumo ya zamani ni wasiwasi.

Unaweza kuorodhesha vikundi vya cgroups v1 na v2 kwa mchakato wowote kwa kuangalia faili yake ya cgroup katika /proc/\<pid>. Unaweza kuanza kwa kuangalia vikundi vya cgroups ya kikao chako cha shell kwa amri hii:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
Muundo wa matokeo ni kama ifuatavyo:

- **Nambari 2-12**: cgroups v1, kila mstari unawakilisha cgroup tofauti. Wadhibiti kwa hizi zinatajwa karibu na nambari.
- **Nambari 1**: Pia cgroups v1, lakini kwa madhumuni ya usimamizi tu (kama ilivyowekwa na, kwa mfano, systemd), na haina mdhibiti.
- **Nambari 0**: Inawakilisha cgroups v2. Hakuna wadhibiti waliotajwa, na mstari huu ni maalum kwa mifumo inayotumia tu cgroups v2.
- **Majina ni ya kihierarkia**, yanafanana na njia za faili, yanayoonyesha muundo na uhusiano kati ya cgroups tofauti.
- **Majina kama vile /user.slice au /system.slice** yanabainisha uainishaji wa cgroups, na user.slice kwa kawaida ni kwa vikao vya kuingia vinavyosimamiwa na systemd na system.slice kwa huduma za mfumo.

### Kuangalia cgroups

Kwa kawaida, mfumo wa faili hutumiwa kufikia **cgroups**, tofauti na kiolesura cha wito cha mfumo wa Unix kinachotumiwa kwa kawaida kwa mwingiliano wa kernel. Ili kuchunguza usanidi wa cgroup wa kikao cha shell, mtu anapaswa kuchunguza faili ya **/proc/self/cgroup**, ambayo inaonyesha cgroup ya kikao cha shell. Kisha, kwa kwenda kwenye saraka ya **/sys/fs/cgroup** (au **`/sys/fs/cgroup/unified`**) na kupata saraka ambayo inashiriki jina la cgroup, mtu anaweza kuona mipangilio mbalimbali na habari ya matumizi ya rasilimali inayohusiana na cgroup.

![Mfumo wa Faili wa Cgroup](../../../.gitbook/assets/image%20(10)%20(2)%20(2).png)

Faili muhimu za kiolesura cha cgroups zina kipimo cha awali cha **cgroup**. Faili ya **cgroup.procs**, ambayo inaweza kuonekana kwa kutumia amri za kawaida kama cat, inaorodhesha michakato ndani ya cgroup. Faili nyingine, **cgroup.threads**, ina habari za nyuzi.

![Cgroup Procs](../../../.gitbook/assets/image%20(1)%20(1)%20(5).png)

Cgroups zinazosimamia vikao vya shell kwa kawaida zina wadhibiti wawili ambao hurekebisha matumizi ya kumbukumbu na idadi ya michakato. Ili kuingiliana na mdhibiti, faili zinazobeba kipimo cha awali cha mdhibiti zinapaswa kuchunguzwa. Kwa mfano, **pids.current** itatumika kuangalia idadi ya nyuzi katika cgroup.

![Cgroup Memory](../../../.gitbook/assets/image%20(3)%20(5).png)

Ishara ya **max** katika thamani inaonyesha kutokuwepo kwa kikomo maalum kwa cgroup. Walakini, kutokana na muundo wa kihierarkia wa cgroups, vikwazo vinaweza kuwekwa na cgroup katika kiwango cha chini katika muundo wa saraka.


### Kubadilisha na Kuunda cgroups

Michakato inapewa cgroups kwa **kuandika Kitambulisho cha Mchakato (PID) yao kwenye faili ya `cgroup.procs`**. Hii inahitaji mamlaka ya mizizi. Kwa mfano, kuongeza mchakato:
```bash
echo [pid] > cgroup.procs
```
Vivyo hivyo, **kubadilisha sifa za cgroup, kama kuweka kikomo cha PID**, hufanywa kwa kuandika thamani inayotaka kwenye faili husika. Ili kuweka kiwango cha juu cha PIDs 3,000 kwa cgroup:
```bash
echo 3000 > pids.max
```
**Kuunda cgroups mpya** kunahusisha kujenga saraka mpya ndani ya muundo wa cgroup, ambayo inasababisha kernel kuzalisha faili za kiolesura zinazohitajika kiotomatiki. Ingawa cgroups bila michakato inayofanya kazi inaweza kuondolewa kwa kutumia `rmdir`, tambua vikwazo fulani:

- **Michakato inaweza kuwekwa tu katika cgroups za majani** (yaani, zilizo ndani zaidi katika muundo wa hiyerakia).
- **Cgroup haiwezi kuwa na kudhibiti ambao haupo kwa mzazi wake**.
- **Wadhibiti kwa cgroups za watoto lazima zitangazwe wazi** katika faili ya `cgroup.subtree_control`. Kwa mfano, kuwezesha wadhibiti wa CPU na PID katika cgroup ya mtoto:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**Kikundi cha mizizi** ni ubaguzi wa sheria hizi, kuruhusu kuweka mchakato moja kwa moja. Hii inaweza kutumika kuondoa michakato kutoka kwa usimamizi wa systemd.

**Ufuatiliaji wa matumizi ya CPU** ndani ya kikundi cha mizizi ni kawaida kupitia faili ya `cpu.stat`, inayoonyesha jumla ya wakati wa CPU uliotumiwa, inayosaidia kufuatilia matumizi kote kwa michakato ya huduma:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption>Takwimu za matumizi ya CPU kama inavyoonyeshwa katika faili ya cpu.stat</figcaption></figure>

## Marejeo
* **Kitabu: Jinsi Linux Inavyofanya Kazi, Toleo la 3: Kila Mtumiaji Mkuu Anapaswa Kujua Na Brian Ward**

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
