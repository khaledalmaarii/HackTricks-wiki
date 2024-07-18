# CGroups

{% hint style="success" %}
Jifunze na zoea AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoea GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Aunga mkono HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

## Taarifa Msingi

**Linux Control Groups**, au **cgroups**, ni kipengele cha kernel ya Linux kinachoruhusu mgawo, kizuizi, na upangaji wa rasilimali za mfumo kama CPU, kumbukumbu, na diski I/O kati ya vikundi vya michakato. Vinatoa mfumo wa **kusimamia na kuisolate matumizi ya rasilimali** ya makusanyo ya michakato, yenye manufaa kwa madhumuni kama kizuizi cha rasilimali, kuisolishwa kwa kazi, na upangaji wa rasilimali kati ya vikundi tofauti vya michakato.

Kuna **matoleo mawili ya cgroups**: toleo la 1 na toleo la 2. Yanaweza kutumika kwa pamoja kwenye mfumo. Tofauti kuu ni kwamba **cgroups toleo la 2** inaleta **muundo wa kihierarkia, kama mti**, kuruhusu ugawaji wa rasilimali wenye undani zaidi kati ya vikundi vya michakato. Aidha, toleo la 2 linaletea maboresho mbalimbali, ikiwa ni pamoja na:

Mbali na muundo mpya wa kihierarkia, cgroups toleo la 2 pia lilileta **mabadiliko na maboresho mengine kadhaa**, kama vile msaada kwa **wadhibiti wa rasilimali wapya**, msaada bora kwa programu za zamani, na utendaji ulioboreshwa.

Kwa ujumla, cgroups **toleo la 2 inatoa vipengele zaidi na utendaji bora** kuliko toleo la 1, lakini la mwisho bado linaweza kutumika katika hali fulani ambapo utangamano na mifumo ya zamani unahitajika.

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
### Kuangalia cgroups

Mfumo wa faili kawaida hutumiwa kwa kupata **cgroups**, ikiondoka kutoka kwa kiolesura cha wito cha mfumo wa Unix kinachotumiwa kwa kawaida kwa mwingiliano wa kernel. Ili kuchunguza usanidi wa cgroup wa shell, mtu anapaswa kuchunguza faili ya **/proc/self/cgroup**, ambayo inaonyesha cgroup ya shell. Kisha, kwa kwenda kwenye saraka ya **/sys/fs/cgroup** (au **`/sys/fs/cgroup/unified`**) na kupata saraka inayoshiriki jina la cgroup, mtu anaweza kuona mipangilio mbalimbali na habari ya matumizi ya rasilimali inayofaa kwa cgroup hiyo.

![Mfumo wa Faili wa Cgroup](<../../../.gitbook/assets/image (1128).png>)

Faili muhimu za kiolesura kwa cgroups zinaambatana na **cgroup**. Faili ya **cgroup.procs**, ambayo inaweza kuonekana na amri za kawaida kama vile cat, inaorodhesha michakato ndani ya cgroup. Faili nyingine, **cgroup.threads**, inajumuisha habari za mchakato.

![Cgroup Procs](<../../../.gitbook/assets/image (281).png>)

Cgroups zinazosimamia mabaka kawaida huwa na mabamba mawili yanayosimamia matumizi ya kumbukumbu na idadi ya michakato. Ili kuingiliana na mabamba, faili zenye kipimo cha mabamba zinapaswa kushauriwa. Kwa mfano, **pids.current** ingetajwa kuthibitisha idadi ya mchakato katika cgroup.

![Kumbukumbu ya Cgroup](<../../../.gitbook/assets/image (677).png>)

Ishara ya **max** katika thamani inapendekeza kutokuwepo kwa kikomo maalum kwa cgroup. Hata hivyo, kutokana na muundo wa kihierarkia wa cgroups, vikomo vinaweza kuwekwa na cgroup katika kiwango cha chini katika muundo wa saraka.

### Kubadilisha na Kuunda cgroups

Michakato hupewa cgroups kwa **kuandika Kitambulisho cha Mchakato (PID) yao kwenye faili ya `cgroup.procs`**. Hii inahitaji mamlaka ya mzizi. Kwa mfano, kuongeza mchakato:
```bash
echo [pid] > cgroup.procs
```
Vivyo hivyo, **kurekebisha sifa za cgroup, kama vile kuweka kikomo cha PID**, hufanywa kwa kuandika thamani inayotakikana kwenye faili husika. Ili kuweka kiwango cha juu cha PIDs 3,000 kwa cgroup:
```bash
echo 3000 > pids.max
```
**Kujenga vikundi vya cgroups** kunahusisha kutengeneza saraka mpya ndani ya muundo wa cgroup, ambayo inachochea kernel kutengeneza faili za interface muhimu kiotomatiki. Ingawa cgroups bila michakato inayofanya kazi inaweza kuondolewa kwa `rmdir`, tambua vikwazo fulani:

* **Michakato inaweza kuwekwa tu katika vikundi vya majani** (yaani, vile vilivyo ndani zaidi katika muundo).
* **Cgroup haiwezi kuwa na kudhibiti mwenzi ambayo haipo kwenye mzazi wake**.
* **Wadhibiti kwa vikundi vya watoto lazima zitangazwe wazi** katika faili ya `cgroup.subtree_control`. Kwa mfano, kuwezesha wadhibiti wa CPU na PID katika kikundi cha mtoto:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**Root cgroup** ni ubaguzi wa sheria hizi, kuruhusu mahali pa moja kwa moja kwa mchakato. Hii inaweza kutumika kuondoa michakato kutoka kwa usimamizi wa systemd.

**Kufuatilia matumizi ya CPU** ndani ya cgroup inawezekana kupitia faili ya `cpu.stat`, inayoonyesha jumla ya muda wa CPU uliotumiwa, inayosaidia kufuatilia matumizi kote kwa michakato ya huduma:

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>Takwimu za matumizi ya CPU kama inavyoonekana kwenye faili ya cpu.stat</p></figcaption></figure>

## Marejeo

* **Kitabu: Jinsi Linux Inavyofanya Kazi, Toleo la 3: Kila Mtu Mwenye Mamlaka ya Juu Anapaswa Kujua Na Brian Ward**
