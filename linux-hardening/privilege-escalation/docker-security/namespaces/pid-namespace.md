# Nafasi ya PID

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

Nafasi ya PID (Process IDentifier) ni kipengele katika kernel ya Linux kinachotoa kujitenga kwa michakato kwa kuwezesha kikundi cha michakato kuwa na seti yao ya PIDs ya kipekee, tofauti na PIDs katika nafasi nyingine. Hii ni muhimu sana katika uwekaji wa kontena, ambapo kujitenga kwa michakato ni muhimu kwa usalama na usimamizi wa rasilimali.

Wakati nafasi mpya ya PID inapoundwa, michakato ya kwanza katika nafasi hiyo hupewa PID 1. Michakato hii inakuwa michakato ya "init" ya nafasi mpya na inawajibika kwa usimamizi wa michakato mingine ndani ya nafasi hiyo. Kila michakato inayoundwa baadaye ndani ya nafasi hiyo itakuwa na PID ya kipekee ndani ya nafasi hiyo, na PIDs hizi zitakuwa huru na PIDs katika nafasi nyingine.

Kutoka mtazamo wa mchakato ndani ya nafasi ya PID, inaweza kuona tu michakato mingine katika nafasi hiyo hiyo. Haifahamu michakato katika nafasi nyingine, na haiwezi kuingiliana nao kwa kutumia zana za usimamizi wa michakato za jadi (k.m., `kill`, `wait`, nk.). Hii hutoa kiwango cha kujitenga ambacho husaidia kuzuia michakato kuingiliana na kuharibiana.

### Jinsi inavyofanya kazi:

1. Wakati mchakato mpya unapoundwa (k.m., kwa kutumia wito wa mfumo wa `clone()`), mchakato huo unaweza kupewa nafasi mpya au iliyopo ya PID. **Ikiwa nafasi mpya inaundwa, mchakato huo unakuwa mchakato wa "init" wa nafasi hiyo**.
2. **Kernel** inaendeleza **uwekaji kati ya PIDs katika nafasi mpya na PIDs zinazofanana** katika nafasi ya mzazi (yaani, nafasi ambayo nafasi mpya iliumbwa kutoka kwake). Uwekaji huu **inaruhusu kernel kutafsiri PIDs wakati inahitajika**, kama vile wakati wa kutuma ishara kati ya michakato katika nafasi tofauti.
3. **Michakato ndani ya nafasi ya PID inaweza kuona na kuingiliana tu na michakato mingine katika nafasi hiyo hiyo**. Hazifahamu michakato katika nafasi nyingine, na PIDs zao ni za kipekee ndani ya nafasi yao.
4. Wakati **nafasi ya PID inapoharibiwa** (k.m., wakati mchakato wa "init" wa nafasi hiyo anatoka), **michakato yote ndani ya nafasi hiyo inafutwa**. Hii inahakikisha kuwa rasilimali zote zinazohusiana na nafasi hiyo zinakamilishwa ipasavyo.

## Maabara:

### Unda Nafasi Tofauti

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Kosa: bash: fork: Haiwezi kutenga kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, kosa linatokea kutokana na jinsi Linux inavyoshughulikia nafasi mpya za PID (Process ID) namespaces. Maelezo muhimu na suluhisho vimeelezewa hapa chini:

1. **Maelezo ya Tatizo**:
- Kernel ya Linux inaruhusu mchakato kuunda nafasi mpya za namespaces kwa kutumia wito wa mfumo wa `unshare`. Walakini, mchakato ambao unaanzisha uundaji wa nafasi mpya ya PID (unaoitwa "mchakato wa unshare") haingii katika nafasi mpya; ni mchakato wake wa watoto tu ndio unaingia.
- Kukimbia `%unshare -p /bin/bash%` kunaanza `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na mchakato wake wa watoto wako katika nafasi ya PID ya awali.
- Mchakato wa kwanza wa watoto wa `/bin/bash` katika nafasi mpya ya PID inakuwa PID 1. Wakati mchakato huu unatoka, husababisha kusafisha kwa nafasi hiyo ikiwa hakuna michakato mingine, kwani PID 1 ina jukumu maalum la kuwachukua michakato ya yatima. Kernel ya Linux kisha itazima ugawaji wa PID katika nafasi hiyo.

2. **Matokeo**:
- Kutoka kwa mchakato wa PID 1 katika nafasi mpya husababisha kusafisha kwa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kushindwa kwa kazi ya `alloc_pid` kuweka PID mpya wakati wa kuunda mchakato mpya, na kusababisha kosa la "Haiwezi kutenga kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` na `unshare`. Chaguo hili linasababisha `unshare` kufanya mchakato mpya baada ya kuunda nafasi mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kuhakikisha kuwa amri ya `unshare` yenyewe inakuwa PID 1 katika nafasi mpya. `/bin/bash` na mchakato wake wa watoto wako salama ndani ya nafasi hii mpya, kuzuia kutoka kwa kutoka mapema kwa PID 1 na kuruhusu ugawaji wa PID kawaida.

Kwa kuhakikisha kuwa `unshare` inaendeshwa na bendera ya `-f`, nafasi mpya ya PID inasimamiwa kwa usahihi, kuruhusu `/bin/bash` na michakato yake ya watoto kufanya kazi bila kukutana na kosa la kutenga kumbukumbu.

</details>

Kwa kusakinisha kipengele kipya cha mfumo wa faili ya `/proc` ikiwa unatumia paramu `--mount-proc`, unahakikisha kuwa nafasi mpya ya kufunga ina **mtazamo sahihi na uliojitosheleza wa habari za michakato maalum kwa nafasi hiyo**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Angalia ni kwenye namespace gani mchakato wako uko

Unaweza kuangalia ni kwenye namespace gani mchakato wako uko kwa kutumia amri ifuatayo:

```bash
cat /proc/$$/status | grep NSpid
```

Amri hii itakupa habari kuhusu namespace ya mchakato wako. Ikiwa mchakato uko kwenye pid namespace, utaona matokeo kama haya:

```
NSpid:	0	1	2	3	4	5	6	7
```

Ikiwa mchakato uko kwenye pid namespace, idadi ya pid itaonyeshwa.
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Tafuta majina yote ya PID namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Tafadhali kumbuka kuwa mtumiaji wa mizizi kutoka kwenye jina la nafasi ya PID ya awali (chaguo-msingi) anaweza kuona michakato yote, hata ile katika nafasi mpya za PID, ndio sababu tunaweza kuona nafasi zote za PID.

### Ingia ndani ya nafasi ya PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Unapoingia ndani ya kipekee cha PID kutoka kwenye kipekee cha msingi, bado utaweza kuona michakato yote. Na michakato kutoka kwenye kipekee hicho cha PID itaweza kuona bash mpya kwenye kipekee hicho cha PID.

Pia, unaweza **kuingia kwenye kipekee cha michakato mingine ya PID ikiwa wewe ni mtumiaji mkuu**. Na huwezi **kuingia** kwenye kipekee nyingine **bila kigeuzi** kinachoelekeza kwake (kama vile `/proc/self/ns/pid`)

## Marejeo
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
