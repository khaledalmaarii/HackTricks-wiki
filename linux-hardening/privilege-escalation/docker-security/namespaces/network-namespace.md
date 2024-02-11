# Nafasi ya Mtandao

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

Nafasi ya mtandao ni kipengele cha kernel ya Linux kinachotoa kujitenga kwa safu ya mtandao, kuruhusu **kila nafasi ya mtandao kuwa na usanidi wake wa mtandao huru**, interface, anwani za IP, meza za kuelekeza, na sheria za firewall. Kujitenga huku kunafaa katika mazingira mbalimbali, kama vile kubebeshaji, ambapo kila kibebeshaji kinapaswa kuwa na usanidi wake wa mtandao, huru na mabebeshaji mengine na mfumo wa mwenyeji.

### Jinsi inavyofanya kazi:

1. Wakati nafasi mpya ya mtandao inapoundwa, inaanza na **safu ya mtandao iliyotengwa kabisa**, bila kuwa na interface za mtandao isipokuwa kwa interface ya loopback (lo). Hii inamaanisha kuwa michakato inayofanya kazi katika nafasi mpya ya mtandao haiwezi kuwasiliana na michakato katika nafasi nyingine au mfumo wa mwenyeji kwa chaguo-msingi.
2. **Interface za mtandao za kubuni**, kama vile jozi za veth, zinaweza kuundwa na kuhamishwa kati ya nafasi za mtandao. Hii inaruhusu kuweka uunganisho wa mtandao kati ya nafasi au kati ya nafasi na mfumo wa mwenyeji. Kwa mfano, mwisho mmoja wa jozi ya veth unaweza kuwekwa katika nafasi ya mtandao ya kontena, na mwisho mwingine unaweza kuunganishwa na **daraja** au interface nyingine ya mtandao katika nafasi ya mwenyeji, ikitoa uunganisho wa mtandao kwa kontena.
3. Interface za mtandao ndani ya nafasi zinaweza kuwa na **anwani zao za IP, meza za kuelekeza, na sheria za firewall**, huru na nafasi nyingine. Hii inaruhusu michakato katika nafasi tofauti za mtandao kuwa na usanidi tofauti wa mtandao na kufanya kazi kana kwamba inafanya kazi kwenye mifumo tofauti ya mtandao.
4. Michakato inaweza kuhamia kati ya nafasi kwa kutumia wito wa mfumo wa `setns()`, au kuunda nafasi mpya kwa kutumia wito wa mfumo wa `unshare()` au `clone()` na bendera ya `CLONE_NEWNET`. Wakati michakato inahamia kwenye nafasi mpya au kuunda moja, itaanza kutumia usanidi wa mtandao na interface zinazohusiana na nafasi hiyo.

## Maabara:

### Unda Nafasi Tofauti

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Kwa kusakinisha kifungu kipya cha mfumo wa faili ya `/proc` ikiwa unatumia paramu `--mount-proc`, unahakikisha kuwa kifungu kipya cha kufunga kinaona **taarifa sahihi na iliyotengwa ya mchakato maalum kwa kifungu hicho**.

<details>

<summary>Kosa: bash: fork: Haiwezi kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, kosa linatokea kutokana na jinsi Linux inavyoshughulikia nafasi mpya za PID (Process ID). Maelezo muhimu na suluhisho vimeelezewa hapa chini:

1. **Maelezo ya Tatizo**:
- Kernel ya Linux inaruhusu mchakato kuunda nafasi mpya za kutumia wito wa mfumo wa `unshare`. Walakini, mchakato ambao unaanzisha uundaji wa nafasi mpya ya PID (inayojulikana kama mchakato wa "unshare") haingii katika nafasi mpya; ni mchakato wake wa watoto tu ndio unaingia.
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
# Run ifconfig or ip -a
```
### Angalia kwenye namespace gani mchakato wako uko

Unaweza kuangalia kwenye namespace gani mchakato wako uko kwa kutumia amri ifuatayo:

```bash
ls -l /proc/<PID>/ns/
```

Badilisha `<PID>` na kitambulisho cha mchakato unayotaka kuangalia. Amri hii itakuonyesha viungo kwa namespace tofauti ambazo mchakato wako amehusishwa nazo.
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Tafuta majina yote ya nafasi za mtandao

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Ingia ndani ya kipeperushi cha mtandao

{% endcode %}
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Pia, unaweza **ingia kwenye namespace nyingine ya mchakato ikiwa wewe ni root**. Na huwezi **kuingia** kwenye namespace nyingine **bila kigeuzi** kinachoelekeza kwake (kama vile `/proc/self/ns/net`).

## Marejeo
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
