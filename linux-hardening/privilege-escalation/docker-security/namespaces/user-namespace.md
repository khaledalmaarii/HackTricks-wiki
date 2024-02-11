# User Namespace

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

User Namespace ni kipengele cha kernel ya Linux ambacho **hutoa kujitenga kwa ramani za kitambulisho cha mtumiaji na kikundi**, kuruhusu kila user namespace kuwa na **seti yake ya kitambulisho cha mtumiaji na kikundi**. Kujitenga huku kunawezesha michakato inayotumia user namespaces to **kuwa na mamlaka na umiliki tofauti**, hata kama wanashiriki kitambulisho cha mtumiaji na kikundi sawasawa kwa idadi.

User namespaces ni muhimu sana katika uwekaji wa kontena, ambapo kila kontena inapaswa kuwa na seti yake ya kujitegemea ya kitambulisho cha mtumiaji na kikundi, kuruhusu usalama na kujitenga bora kati ya kontena na mfumo mwenyeji.

### Jinsi inavyofanya kazi:

1. Wakati user namespace mpya inaundwa, **inaanza na seti tupu ya ramani za kitambulisho cha mtumiaji na kikundi**. Hii inamaanisha kuwa mchakato wowote unaotumia user namespace mpya **kwa kuanzia hautakuwa na mamlaka nje ya namespace**.
2. Ramani za kitambulisho zinaweza kuwekwa kati ya kitambulisho cha mtumiaji na kikundi katika user namespace mpya na zile katika namespace ya mzazi (au mwenyeji). Hii **inaruhusu michakato katika user namespace mpya kuwa na mamlaka na umiliki unaolingana na kitambulisho cha mtumiaji na kikundi katika namespace ya mzazi**. Walakini, ramani za kitambulisho zinaweza kuzuiliwa kwa safu na subset maalum za kitambulisho, kuruhusu udhibiti wa kina juu ya mamlaka zinazotolewa kwa michakato katika user namespace mpya.
3. Ndani ya user namespace, **michakato inaweza kuwa na mamlaka kamili ya mizizi (UID 0) kwa shughuli ndani ya namespace**, wakati bado ina mamlaka mdogo nje ya namespace. Hii inaruhusu **kontena kufanya kazi na uwezo kama mizizi ndani ya namespace yake bila kuwa na mamlaka kamili ya mizizi kwenye mfumo mwenyeji**.
4. Michakato inaweza kuhamia kati ya namespaces kwa kutumia wito wa mfumo wa `setns()` au kuunda namespaces mpya kwa kutumia wito wa mfumo wa `unshare()` au `clone()` na bendera ya `CLONE_NEWUSER`. Wakati mchakato unahamia kwenye namespace mpya au kuunda moja, itaanza kutumia ramani za kitambulisho cha mtumiaji na kikundi zinazohusiana na namespace hiyo.

## Maabara:

### Unda Namespaces Tofauti

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Kwa kusakinisha kipengele kipya cha mfumo wa faili ya `/proc` ikiwa unatumia paramu `--mount-proc`, unahakikisha kuwa kipengele kipya cha kufunga kinaona **taarifa sahihi na iliyotengwa ya mchakato maalum kwa kipengele hicho**.

<details>

<summary>Kosa: bash: fork: Haiwezi kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, kosa linatokea kutokana na jinsi Linux inavyoshughulikia nafasi mpya za PID (Process ID). Maelezo muhimu na suluhisho vimeelezewa hapa chini:

1. **Maelezo ya Tatizo**:
- Kernel ya Linux inaruhusu mchakato kuunda nafasi mpya za kutumia wito wa mfumo wa `unshare`. Walakini, mchakato ambao unaanzisha uundaji wa nafasi mpya ya PID (inayojulikana kama mchakato wa "unshare") haingii katika nafasi mpya; ni mchakato wake wa watoto tu ndio unaingia.
- Kukimbia `%unshare -p /bin/bash%` kuanza `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na mchakato wake wa watoto wako katika nafasi ya PID ya awali.
- Mchakato wa kwanza wa watoto wa `/bin/bash` katika nafasi mpya hupata PID 1. Wakati mchakato huu unatoka, husababisha kusafisha kwa nafasi hiyo ikiwa hakuna michakato mingine, kwani PID 1 ina jukumu maalum la kuwachukua michakato yatima. Kernel ya Linux kisha itazima ugawaji wa PID katika nafasi hiyo.

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
Kutumia user namespace, kifaa cha Docker kinahitaji kuanzishwa na **`--userns-remap=default`** (Katika ubuntu 14.04, hii inaweza kufanywa kwa kubadilisha `/etc/default/docker` na kisha kutekeleza `sudo service docker restart`)

### &#x20;Angalia ni namespace gani mchakato wako uko ndani yake
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Inawezekana kuangalia ramani ya mtumiaji kutoka kwenye chombo cha docker kwa kutumia:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Au kutoka kwenye mwenyeji na:
```bash
cat /proc/<pid>/uid_map
```
### Tafuta majina yote ya nafasi za mtumiaji

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Ingia ndani ya jina nafasi ya mtumiaji

{% endcode %}
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Pia, unaweza **ingia kwenye namespace ya mchakato mwingine ikiwa wewe ni root**. Na huwezi **kuingia** kwenye namespace nyingine **bila kigeuzi** kinachoelekeza kwake (kama vile `/proc/self/ns/user`).

### Unda namespace mpya ya mtumiaji (na ramani) 

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Kurejesha Uwezo

Katika kesi ya majina ya watumiaji, **wakati jina jipya la mtumiaji linapoundwa, mchakato unaotumia jina hilo linapewa seti kamili ya uwezo ndani ya jina hilo**. Uwezo huu unaruhusu mchakato kufanya operesheni za kihalali kama vile **kufunga** **mfumo wa faili**, kuunda vifaa, au kubadilisha umiliki wa faili, lakini **tu ndani ya muktadha wa jina lake la mtumiaji**.

Kwa mfano, wakati una uwezo wa `CAP_SYS_ADMIN` ndani ya jina la mtumiaji, unaweza kufanya operesheni ambazo kwa kawaida zinahitaji uwezo huu, kama vile kufunga mfumo wa faili, lakini tu ndani ya muktadha wa jina lako la mtumiaji. Operesheni yoyote unayofanya na uwezo huu haitaathiri mfumo mwenyeji au majina mengine.

{% hint style="warning" %}
Kwa hiyo, hata kama kupata mchakato mpya ndani ya Jina jipya la Mtumiaji **kutakupa uwezo wote tena** (CapEff: 000001ffffffffff), kimsingi unaweza **kutumia tu wale unaohusiana na jina la mtumiaji** (kama vile kufunga) lakini sio wote. Kwa hiyo, hii pekee haitoshi kutoroka kutoka kwenye kontena ya Docker.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
Probando: 0x143 . . . Error
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
