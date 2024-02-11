# CGroup Namespace

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

CGroup namespace ni kipengele cha kernel ya Linux kinachotoa **kutengwa kwa ierarkia za cgroup kwa michakato inayotumia ndani ya namespace**. Cgroups, kifupi cha **control groups**, ni kipengele cha kernel kinachoruhusu kuandaa michakato katika vikundi vya ierarkia ili kusimamia na kutekeleza **mipaka kwenye rasilimali za mfumo** kama vile CPU, kumbukumbu, na I/O.

Ingawa cgroup namespaces sio aina tofauti ya namespace kama zile tulizojadili hapo awali (PID, mount, mtandao, nk), zina uhusiano na dhana ya kutengwa kwa namespace. **Cgroup namespaces hufanya kuonekana kwa ierarkia ya cgroup kuwa ya kubuni**, hivyo michakato inayotumia ndani ya cgroup namespace inaona ierarkia tofauti ya cgroup ikilinganishwa na michakato inayotumia kwenye mwenyeji au namespaces nyingine.

### Jinsi inavyofanya kazi:

1. Wakati namespace mpya ya cgroup inaundwa, **inaanza na mtazamo wa ierarkia ya cgroup kulingana na cgroup ya michakato inayounda**. Hii inamaanisha kuwa michakato inayotumia ndani ya cgroup namespace mpya itaona tu sehemu ya ierarkia ya cgroup nzima, iliyopunguzwa kwa mti wa cgroup ulioanzishwa na cgroup ya michakato inayounda.
2. Michakato ndani ya cgroup namespace itaona **cgroup yao wenyewe kama mzizi wa ierarkia**. Hii inamaanisha kuwa, kutoka mtazamo wa michakato ndani ya namespace, cgroup yao wenyewe inaonekana kama mzizi, na hawawezi kuona au kufikia cgroups nje ya mti wao wenyewe.
3. Cgroup namespaces hazitoi moja kwa moja kutengwa kwa rasilimali; **zinafanya tu kuonekana kwa ierarkia ya cgroup kuwa ya kubuni**. **Kudhibiti na kutenga rasilimali bado kunatekelezwa na** subsistemi za cgroup (k.m., cpu, kumbukumbu, nk) wenyewe.

Kwa habari zaidi kuhusu CGroups angalia:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Maabara:

### Unda Namespaces Tofauti

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Kwa kusakinisha kifungu kipya cha mfumo wa faili ya `/proc` ikiwa unatumia paramu `--mount-proc`, unahakikisha kuwa kifungu kipya cha kuziba kinaona **taarifa sahihi na iliyotengwa ya mchakato maalum kwa kifungu hicho**.

<details>

<summary>Kosa: bash: fork: Haiwezi kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, kosa linatokea kutokana na jinsi Linux inavyoshughulikia nafasi mpya za PID (Process ID). Maelezo muhimu na suluhisho vimeelezewa hapa chini:

1. **Maelezo ya Tatizo**:
- Kernel ya Linux inaruhusu mchakato kuunda nafasi mpya za kutumia `unshare` wito wa mfumo. Walakini, mchakato ambao unaanzisha uundaji wa nafasi mpya ya PID (inayojulikana kama mchakato wa "unshare") haingii katika nafasi mpya; ni mchakato wake wa watoto tu ndio unaingia.
- Kukimbia `%unshare -p /bin/bash%` kuanza `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na mchakato wake wa watoto wako katika nafasi ya PID ya awali.
- Mchakato wa kwanza wa watoto wa `/bin/bash` katika nafasi mpya hufanywa kuwa PID 1. Wakati mchakato huu unatoka, husababisha kusafisha kwa nafasi hiyo ikiwa hakuna michakato mingine, kwani PID 1 ina jukumu maalum la kuwachukua michakato yatima. Kernel ya Linux kisha itazima ugawaji wa PID katika nafasi hiyo.

2. **Matokeo**:
- Kutoka kwa kutoka kwa PID 1 katika nafasi mpya kunasababisha kusafisha kwa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kushindwa kwa kazi ya `alloc_pid` kuweka PID mpya wakati wa kuunda mchakato mpya, na kusababisha kosa la "Haiwezi kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` na `unshare`. Chaguo hili linamfanya `unshare` kugawanya mchakato mpya baada ya kuunda nafasi mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kuwa amri ya `unshare` yenyewe inakuwa PID 1 katika nafasi mpya. `/bin/bash` na mchakato wake wa watoto kisha wako salama ndani ya nafasi hii mpya, kuzuia kutoka kwa kutoka mapema kwa PID 1 na kuruhusu ugawaji wa PID kawaida.

Kwa kuhakikisha kuwa `unshare` inatekelezwa na bendera ya `-f`, nafasi mpya ya PID inasimamiwa kwa usahihi, kuruhusu `/bin/bash` na michakato yake ya chini kufanya kazi bila kukutana na kosa la ugawaji wa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Angalia ni kwenye namespace gani mchakato wako uko

To check which namespace your process is in, you can use the following command:

Kuangalia ni kwenye namespace gani mchakato wako uko, unaweza kutumia amri ifuatayo:

```bash
cat /proc/$$/cgroup
```

This command will display the cgroup namespace information for your process.
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Tafuta majina yote ya CGroup namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Ingia ndani ya CGroup namespace

{% endcode %}
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Pia, unaweza **ingia kwenye namespace ya mchakato mwingine ikiwa wewe ni root**. Na huwezi **kuingia** kwenye namespace nyingine **bila kigeuzi** kinachoelekeza kwake (kama vile `/proc/self/ns/cgroup`).

## Marejeo
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
