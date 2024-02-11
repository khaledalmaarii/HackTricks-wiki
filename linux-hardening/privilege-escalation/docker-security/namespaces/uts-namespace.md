# UTS Namespace

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

UTS (UNIX Time-Sharing System) namespace ni kipengele cha kernel ya Linux kinachotoa **kutengwa kwa vitambulisho viwili vya mfumo**: **jina la mwenyeji** na **jina la kikoa la NIS** (Network Information Service). Kutengwa huku kunaruhusu kila UTS namespace kuwa na **jina la mwenyeji na kikoa cha NIS cha kujitegemea**, ambacho ni muhimu hasa katika mazingira ya kubebwa ambapo kila kontena inapaswa kuonekana kama mfumo tofauti na jina lake la mwenyeji.

### Jinsi inavyofanya kazi:

1. Wakati UTS namespace mpya inapoundwa, inaanza na **nakala ya jina la mwenyeji na kikoa cha NIS kutoka kwa UTS namespace ya mzazi**. Hii inamaanisha kuwa, wakati wa kuundwa, UTS namespace mpya **inashiriki vitambulisho sawa na mzazi wake**. Walakini, mabadiliko yoyote yanayofuata kwenye jina la mwenyeji au kikoa cha NIS ndani ya UTS namespace hayataathiri UTS namespace nyingine.
2. Mchakato ndani ya UTS namespace **unaweza kubadilisha jina la mwenyeji na kikoa cha NIS** kwa kutumia wito wa mfumo wa `sethostname()` na `setdomainname()` mtawaliwa. Mabadiliko haya ni ya ndani kwa UTS namespace na hayawaathiri UTS namespace nyingine au mfumo wa mwenyeji.
3. Mchakato unaweza kuhamia kati ya UTS namespaces kwa kutumia wito wa mfumo wa `setns()` au kuunda UTS namespaces mpya kwa kutumia wito wa mfumo wa `unshare()` au `clone()` na bendera ya `CLONE_NEWUTS`. Wakati mchakato unahamia kwenye UTS namespace mpya au kuunda moja, itaanza kutumia jina la mwenyeji na kikoa cha NIS kinachohusiana na UTS namespace hiyo.

## Maabara:

### Unda UTS Namespaces Tofauti

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Kwa kusakinisha kifungu kipya cha mfumo wa faili ya `/proc` ikiwa unatumia paramu `--mount-proc`, unahakikisha kuwa kifungu kipya cha kufunga kina **mtazamo sahihi na uliojitosheleza wa habari za mchakato maalum kwa kifungu hicho**.

<details>

<summary>Kosa: bash: fork: Haiwezi kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, kosa linatokea kutokana na jinsi Linux inavyoshughulikia nafasi mpya za PID (Process ID). Maelezo muhimu na suluhisho vimeelezewa hapa chini:

1. **Maelezo ya Tatizo**:
- Kernel ya Linux inaruhusu mchakato kuunda nafasi mpya za kutumia `unshare` wito wa mfumo. Walakini, mchakato ambao unaanzisha uundaji wa nafasi mpya ya PID (inayojulikana kama mchakato wa "unshare") haingii katika nafasi mpya; ni mchakato wake wa watoto tu ndio huingia.
- Kukimbia `%unshare -p /bin/bash%` kuanza `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na mchakato wake wa watoto wako katika nafasi ya PID ya awali.
- Mchakato wa kwanza wa watoto wa `/bin/bash` katika nafasi mpya hufanywa kuwa PID 1. Wakati mchakato huu unatoka, husababisha kusafisha kwa nafasi hiyo ikiwa hakuna michakato mingine, kwani PID 1 ina jukumu maalum la kuwachukua michakato yatima. Kernel ya Linux kisha itazima ugawaji wa PID katika nafasi hiyo.

2. **Matokeo**:
- Kutoka kwa kutoka kwa PID 1 katika nafasi mpya kunasababisha kusafisha kwa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kushindwa kwa kazi ya `alloc_pid` kuweka kumbukumbu mpya wakati wa kuunda mchakato mpya, na kusababisha kosa la "Haiwezi kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` na `unshare`. Chaguo hili linamfanya `unshare` kugawanya mchakato mpya baada ya kuunda nafasi mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kuwa amri ya `unshare` yenyewe inakuwa PID 1 katika nafasi mpya. `/bin/bash` na mchakato wake wa watoto kisha wako salama ndani ya nafasi hii mpya, kuzuia kutoka kwa kutoka mapema kwa PID 1 na kuruhusu ugawaji wa PID kawaida.

Kwa kuhakikisha kuwa `unshare` inaendeshwa na bendera ya `-f`, nafasi mpya ya PID inasimamiwa kwa usahihi, kuruhusu `/bin/bash` na michakato yake ya chini kufanya kazi bila kukutana na kosa la ugawaji wa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Angalia kwenye namespace gani mchakato wako uko

To check which namespace your process is in, you can use the following command:

```bash
$ cat /proc/$$/ns/uts
```

This will display the inode number of the UTS (Unix Timesharing System) namespace that your process is currently in.
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Tafuta majina yote ya UTS namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Ingia ndani ya UTS namespace

{% endcode %}
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
Pia, unaweza **ingia kwenye namespace ya mchakato mwingine ikiwa wewe ni root**. Na huwezi **ingia** kwenye namespace nyingine **bila kigeuzi** kinachoelekeza kwake (kama vile `/proc/self/ns/uts`).

### Badilisha jina la mwenyeji
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
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
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
