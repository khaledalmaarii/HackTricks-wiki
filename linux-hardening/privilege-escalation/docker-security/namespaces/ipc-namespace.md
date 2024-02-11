# IPC Namespace

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

Kiwambo cha IPC (Inter-Process Communication) ni kipengele cha kernel ya Linux kinachotoa **kutengwa** kwa vitu vya IPC vya System V, kama vile foleni za ujumbe, sehemu za kumbukumbu zilizoshirikiwa, na ishara. Kutengwa huku kunahakikisha kuwa michakato katika **kiwambo tofauti cha IPC haziwezi kufikia moja kwa moja au kubadilisha vitu vya IPC vya wengine**, kutoa safu ya ziada ya usalama na faragha kati ya vikundi vya michakato.

### Jinsi inavyofanya kazi:

1. Wakati kiwambo kipya cha IPC kinapotengenezwa, kinaanza na **seti kamili ya vitu vya IPC vya System V vilivyotengwa**. Hii inamaanisha kuwa michakato inayotumia kiwambo kipya cha IPC haitaweza kufikia au kuingilia vitu vya IPC katika viwambo vingine au mfumo mwenyeji kwa chaguo-msingi.
2. Vitu vya IPC vilivyoundwa ndani ya kiwambo vinaonekana na **vinapatikana tu kwa michakato ndani ya kiwambo hicho**. Kila kipengele cha IPC kinatambuliwa na ufunguo wa kipekee ndani ya kiwambo chake. Ingawa ufunguo unaweza kuwa sawa katika viwambo tofauti, vitu vyenyewe vimefungwa na haviwezi kufikiwa kati ya viwambo.
3. Michakato inaweza kuhamia kati ya viwambo kwa kutumia wito wa mfumo wa `setns()` au kuunda viwambo vipya kwa kutumia wito wa mfumo wa `unshare()` au `clone()` na bendera ya `CLONE_NEWIPC`. Wakati michakato inahamia kwenye kiwambo kipya au kuunda kimoja, itaanza kutumia vitu vya IPC vinavyohusishwa na kiwambo hicho.

## Maabara:

### Unda Viwambo Tofauti

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Kwa kusakinisha kifungu kipya cha mfumo wa faili ya `/proc` ikiwa unatumia paramu `--mount-proc`, unahakikisha kuwa kifungu kipya cha kufunga kinaona **taarifa sahihi na iliyotengwa ya mchakato maalum kwa kifungu hicho**.

<details>

<summary>Kosa: bash: fork: Haiwezi kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, kosa linatokea kutokana na jinsi Linux inavyoshughulikia nafasi mpya za PID (Process ID). Maelezo muhimu na suluhisho vimeelezewa hapa chini:

1. **Maelezo ya Tatizo**:
- Kernel ya Linux inaruhusu mchakato kuunda nafasi mpya za kutumia `unshare` wito wa mfumo. Walakini, mchakato ambao unaanzisha uundaji wa nafasi mpya ya PID (inayojulikana kama mchakato wa "unshare") haingii katika nafasi mpya; ni mchakato wake wa watoto tu ndio unaingia.
- Kukimbia `%unshare -p /bin/bash%` kuanza `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na mchakato wake wa watoto wako katika nafasi ya PID ya awali.
- Mchakato wa kwanza wa watoto wa `/bin/bash` katika nafasi mpya hufanywa kuwa PID 1. Wakati mchakato huu unapoondoka, husababisha kusafisha kwa nafasi hiyo ikiwa hakuna michakato mingine, kwani PID 1 ina jukumu maalum la kuwachukua michakato yatima. Kernel ya Linux kisha itazima ugawaji wa PID katika nafasi hiyo.

2. **Matokeo**:
- Kutoka kwa PID 1 katika nafasi mpya kunasababisha kusafisha kwa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kushindwa kwa kazi ya `alloc_pid` kuweka PID mpya wakati wa kuunda mchakato mpya, na kusababisha kosa la "Haiwezi kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` na `unshare`. Chaguo hili linamfanya `unshare` kugawanya mchakato mpya baada ya kuunda nafasi mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kuwa amri ya `unshare` yenyewe inakuwa PID 1 katika nafasi mpya. `/bin/bash` na mchakato wake wa watoto wako salama ndani ya nafasi hii mpya, kuzuia kutoka kwa kuondoka mapema kwa PID 1 na kuruhusu ugawaji wa PID kawaida.

Kwa kuhakikisha kuwa `unshare` inatekelezwa na bendera ya `-f`, nafasi mpya ya PID inasimamiwa kwa usahihi, kuruhusu `/bin/bash` na michakato yake ya chini kufanya kazi bila kukutana na kosa la ugawaji wa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Angalia kwenye nafasi gani kundi lako la mchakato liko

Unaweza kuangalia kwenye nafasi gani kundi lako la mchakato liko kwa kutumia amri ifuatayo:

```bash
ls -l /proc/<PID>/ns/
```

Badala ya `<PID>`, weka kitambulisho cha mchakato ambacho unataka kuangalia. Amri hii itakuonyesha viungo kwa kila aina ya nafasi ambazo mchakato huo amehusishwa nazo.
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Tafuta majina yote ya IPC namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Ingia ndani ya nafasi ya IPC

{% endcode %}
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Pia, unaweza **kuingia kwenye namespace ya mchakato mwingine ikiwa wewe ni mtumiaji mkuu**. Na huwezi **kuingia** kwenye namespace nyingine **bila kigeuzi** kinachoelekeza kwake (kama vile `/proc/self/ns/net`).

### Unda kitu cha IPC
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Marejeo
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)



<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
