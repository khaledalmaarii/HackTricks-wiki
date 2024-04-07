# CGroups

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

**Linux Control Groups**, au **cgroups**, ni kipengele cha kernel ya Linux kinachoruhusu ugawaji, kikomo, na upangaji wa rasilimali za mfumo kama CPU, kumbukumbu, na diski I/O kati ya vikundi vya michakato. Wanatoa mfumo wa **kusimamia na kuisolate matumizi ya rasilimali** ya makusanyo ya michakato, yenye manufaa kwa madhumuni kama kikomo cha rasilimali, kuisolate kazi, na upangaji wa rasilimali kati ya vikundi tofauti vya michakato.

Kuna **toleo mbili za cgroups**: toleo la 1 na toleo la 2. Zote zinaweza kutumika kwa pamoja kwenye mfumo. Tofauti kuu ni kwamba **cgroups toleo la 2** inaleta **muundo wa kihierarkia, kama mti**, kuruhusu ugawaji wa rasilimali kati ya vikundi vya michakato kwa undani zaidi. Aidha, toleo la 2 linaletea uboreshaji mbalimbali, ikiwa ni pamoja na:

Mbali na muundo mpya wa kihierarkia, cgroups toleo la 2 pia lilileta **mabadiliko na uboreshaji mwingine**, kama msaada kwa **wachunguzi wa rasilimali wapya**, msaada bora kwa programu za zamani, na utendaji ulioboreshwa.

Kwa ujumla, cgroups **toleo la 2 linaleta vipengele zaidi na utendaji bora** kuliko toleo la 1, lakini la mwisho bado linaweza kutumika katika hali fulani ambapo utangamano na mifumo ya zamani unahitajika.

Unaweza kuorodhesha cgroups za v1 na v2 kwa mchakato wowote kwa kuangalia faili yake ya cgroup katika /proc/\<pid>. Unaweza kuanza kwa kuangalia cgroups za ganda lako na amri hii:
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
```markdown
The output structure is as follows:

* **Nambari 2–12**: cgroups v1, kila mstari ukiwakilisha cgroup tofauti. Watawala kwa hizi zimetajwa karibu na nambari.
* **Nambari 1**: Pia cgroups v1, lakini kwa madhumuni ya usimamizi pekee (imetengenezwa na, k.m., systemd), na haina mtawala.
* **Nambari 0**: Inawakilisha cgroups v2. Hakuna watawala waliotajwa, na mstari huu ni maalum kwa mifumo inayotumia cgroups v2 pekee.
* **Majina ni ya kihierarkia**, yanafanana na njia za faili, yakionyesha muundo na uhusiano kati ya cgroups tofauti.
* **Majina kama /user.slice au /system.slice** yanabainisha aina ya cgroups, na user.slice kwa kawaida ni kwa vikao vya kuingia vinavyosimamiwa na systemd na system.slice kwa huduma za mfumo.

### Kuangalia cgroups

Kawaida mfumo wa faili hutumiwa kufikia **cgroups**, ikiondoka na kawaida ya mwito wa mfumo wa Unix uliotumiwa kwa mwingiliano wa kernel kihistoria. Ili kuchunguza usanidi wa cgroup wa kikao cha shell, mtu anapaswa kutazama faili ya **/proc/self/cgroup**, ambayo inaonyesha cgroup ya kikao cha shell. Kisha, kwa kwenda kwenye saraka ya **/sys/fs/cgroup** (au **`/sys/fs/cgroup/unified`**) na kupata saraka inayoshiriki jina la cgroup, mtu anaweza kuona mipangilio mbalimbali na habari ya matumizi ya rasilimali inayohusiana na cgroup hiyo.

![Mfumo wa Faili wa Cgroup](<../../../.gitbook/assets/image (1125).png>)

Faili muhimu za kiolesura cha cgroups zinaanza na **cgroup**. Faili ya **cgroup.procs**, ambayo inaweza kuonekana kwa kutumia amri za kawaida kama cat, inaorodhesha michakato ndani ya cgroup. Faili nyingine, **cgroup.threads**, inajumuisha habari za mchakato.

![Cgroup Procs](<../../../.gitbook/assets/image (278).png>)

Cgroups zinazosimamia mabaka kawaida huwa na watawala wawili wanaosimamia matumizi ya kumbukumbu na idadi ya michakato. Ili kuingiliana na mtawala, faili zenye kipimo cha mtawala zinapaswa kushauriwa. Kwa mfano, **pids.current** ingetajwa kuthibitisha idadi ya mabaka katika cgroup.

![Kumbukumbu ya Cgroup](<../../../.gitbook/assets/image (674).png>)

Ishara ya **max** katika thamani inaashiria kutokuwepo kwa kikomo maalum kwa cgroup. Hata hivyo, kutokana na muundo wa kihierarkia wa cgroups, vikomo vinaweza kuwekwa na cgroup katika kiwango cha chini katika muundo wa saraka.

### Kubadilisha na Kuunda cgroups

Michakato hupangiwa cgroups kwa **kuandika Kitambulisho cha Mchakato (PID) yao kwenye faili ya `cgroup.procs`**. Hii inahitaji mamlaka ya mzizi. Kwa mfano, kuongeza mchakato:
```
```bash
echo [pid] > cgroup.procs
```
Vivyo hivyo, **kurekebisha sifa za cgroup, kama vile kuweka kikomo cha PID**, hufanywa kwa kuandika thamani inayotakiwa kwenye faili husika. Ili kuweka kiwango cha juu cha PIDs 3,000 kwa cgroup:
```bash
echo 3000 > pids.max
```
**Kuunda cgroups mpya** kunahusisha kutengeneza saraka mpya ndani ya mfuatano wa cgroup, ambayo inachochea kernel kutengeneza faili za interface zinazohitajika kiotomatiki. Ingawa cgroups bila michakato inayofanya kazi inaweza kuondolewa kwa `rmdir`, tambua vikwazo fulani:

* **Michakato inaweza kuwekwa tu katika cgroups za majani** (yaani, zile zilizo ndani zaidi katika mfuatano).
* **Cgroup haiwezi kuwa na kudhibiti mwenzi katika mzazi wake**.
* **Wadhibiti kwa cgroups za watoto lazima zitangazwe wazi** katika faili ya `cgroup.subtree_control`. Kwa mfano, kuwezesha wadhibiti wa CPU na PID katika cgroup ya mtoto:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**Kikundi cha mzizi** ni ubaguzi wa sheria hizi, kuruhusu mahali pa moja kwa moja kwa mchakato. Hii inaweza kutumika kuondoa michakato kutoka kwa usimamizi wa systemd.

**Kufuatilia matumizi ya CPU** ndani ya kikundi cha cgroup inawezekana kupitia faili ya `cpu.stat`, inayoonyesha jumla ya muda wa CPU uliotumiwa, inayosaidia kufuatilia matumizi kote kwa michakato ya huduma:

<figure><img src="../../../.gitbook/assets/image (905).png" alt=""><figcaption><p>Takwimu za matumizi ya CPU kama inavyoonyeshwa katika faili ya cpu.stat</p></figcaption></figure>

## Marejeo

* **Kitabu: Jinsi Linux Inavyofanya Kazi, Toleo la 3: Kila Mtu Mwenye Mamlaka ya Juu Anapaswa Kujua Na Brian Ward**
