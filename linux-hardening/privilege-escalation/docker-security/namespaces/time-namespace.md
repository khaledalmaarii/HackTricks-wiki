# Nafasi ya Wakati

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

Nafasi ya wakati katika Linux inaruhusu kurekebisha muda wa mfumo na saa ya kuanza kwa kila nafasi. Mara nyingi hutumiwa katika vyombo vya Linux kubadilisha tarehe/wakati ndani ya chombo na kurekebisha saa baada ya kurejesha kutoka kwa checkpoint au snapshot.

## Maabara:

### Unda Nafasi Tofauti

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Kwa kusakinisha kifungu kipya cha mfumo wa faili ya `/proc` ikiwa unatumia paramu `--mount-proc`, unahakikisha kuwa kifungu kipya cha kufunga kina **mtazamo sahihi na uliojitosheleza wa habari za mchakato maalum kwa kifungu hicho**.

<details>

<summary>Kosa: bash: fork: Haiwezi kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, kosa linatokea kutokana na jinsi Linux inavyoshughulikia nafasi mpya za PID (Process ID). Maelezo muhimu na suluhisho vimeelezewa hapa chini:

1. **Maelezo ya Tatizo**:
- Kernel ya Linux inaruhusu mchakato kuunda nafasi mpya za kutumia `unshare` wito wa mfumo. Walakini, mchakato ambao unaanzisha uundaji wa nafasi mpya ya PID (inayojulikana kama mchakato wa "unshare") haingii katika nafasi mpya; ni mchakato wake wa watoto tu ndio unaingia.
- Kukimbia `%unshare -p /bin/bash%` kuanza `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na mchakato wake wa watoto wako katika nafasi ya PID ya awali.
- Mchakato wa kwanza wa watoto wa `/bin/bash` katika nafasi mpya hufanywa kuwa PID 1. Wakati mchakato huu unatoka, husababisha kusafisha kwa nafasi hiyo ikiwa hakuna michakato mingine, kwani PID 1 ina jukumu maalum la kuwachukua michakato yatima. Kernel ya Linux kisha italemaza ugawaji wa PID katika nafasi hiyo.

2. **Matokeo**:
- Kutoka kwa mchakato wa PID 1 katika nafasi mpya kunasababisha kusafisha kwa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kushindwa kwa kazi ya `alloc_pid` kuweka PID mpya wakati wa kuunda mchakato mpya, na kusababisha kosa la "Haiwezi kugawa kumbukumbu".

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

Unaweza kuangalia kwenye namespace gani mchakato wako uko kwa kutumia amri ifuatayo:

```bash
cat /proc/$$/ns/pid
```

Amri hii itakupa habari kuhusu namespace ambayo mchakato wako uko.
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Tafuta majina yote ya Time namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Ingia ndani ya kipekee cha Muda

{% endcode %}
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
Pia, unaweza **ingia kwenye namespace ya mchakato mwingine ikiwa wewe ni root**. Na huwezi **kuingia** kwenye namespace nyingine **bila kigeuzi** kinachoelekeza kwake (kama vile `/proc/self/ns/net`).


## Marejeo
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
* [https://www.phoronix.com/news/Linux-Time-Namespace-Coming](https://www.phoronix.com/news/Linux-Time-Namespace-Coming)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
