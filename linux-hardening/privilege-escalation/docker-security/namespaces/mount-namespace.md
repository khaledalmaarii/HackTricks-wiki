# Nafasi ya Kufunga

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

Nafasi ya kufunga ni kipengele cha kernel ya Linux kinachotoa kujitenga kwa sehemu za kufunga mfumo wa faili zinazoonekana na kikundi cha michakato. Kila nafasi ya kufunga ina seti yake ya sehemu za kufunga mfumo wa faili, na **mabadiliko kwenye sehemu za kufunga kwenye nafasi moja hayawaathiri nafasi nyingine**. Hii inamaanisha kuwa michakato inayotumia nafasi tofauti za kufunga inaweza kuwa na maoni tofauti ya muundo wa mfumo wa faili.

Nafasi za kufunga ni muhimu sana katika uwekaji wa kontena, ambapo kila kontena inapaswa kuwa na mfumo wake wa faili na usanidi, ukiwa umetengwa na kontena zingine na mfumo wa mwenyeji.

### Jinsi inavyofanya kazi:

1. Wakati nafasi mpya ya kufunga inapoundwa, inaanzishwa na **nakala ya sehemu za kufunga kutoka kwenye nafasi ya mzazi**. Hii inamaanisha kuwa, wakati wa kuundwa, nafasi mpya inashiriki maoni sawa ya mfumo wa faili kama mzazi wake. Walakini, mabadiliko yoyote yanayofuata kwenye sehemu za kufunga ndani ya nafasi hayataathiri mzazi au nafasi nyingine.
2. Wakati michakato inapobadilisha sehemu ya kufunga ndani ya nafasi yake, kama vile kufunga au kufungua mfumo wa faili, **mabadiliko ni ya ndani ya nafasi hiyo** na hayawaathiri nafasi nyingine. Hii inaruhusu kila nafasi kuwa na muundo wake wa mfumo wa faili huru.
3. Michakato inaweza kuhamia kati ya nafasi kwa kutumia wito wa mfumo wa `setns()`, au kuunda nafasi mpya kwa kutumia wito wa mfumo wa `unshare()` au `clone()` na bendera ya `CLONE_NEWNS`. Wakati michakato inahamia kwenye nafasi mpya au kuunda moja, itaanza kutumia sehemu za kufunga zinazohusiana na nafasi hiyo.
4. **Vidokezo vya faili na inode vimeshiriki kati ya nafasi**, maana yake ikiwa michakato katika nafasi moja ina kipeperushi cha faili kilichofunguliwa kinachoelekeza kwa faili, inaweza **kupitisha kipeperushi hicho cha faili** kwa michakato katika nafasi nyingine, na **michakato yote itapata ufikiaji sawa wa faili hiyo**. Walakini, njia ya faili inaweza kutofautiana kati ya nafasi hizo kutokana na tofauti katika sehemu za kufunga.

## Maabara:

### Unda Nafasi Tofauti

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Kwa kusakinisha kipengele kipya cha mfumo wa faili ya `/proc` ikiwa unatumia paramu `--mount-proc`, unahakikisha kuwa kipengele kipya cha kufunga kina **mtazamo sahihi na uliojitosheleza wa habari za mchakato maalum kwa kipengele hicho**.

<details>

<summary>Kosa: bash: fork: Haiwezi kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, kosa linatokea kutokana na jinsi Linux inavyoshughulikia nafasi mpya za PID (Process ID) namespaces. Maelezo muhimu na suluhisho vimeelezewa hapa chini:

1. **Maelezo ya Tatizo**:
- Kernel ya Linux inaruhusu mchakato kuunda nafasi mpya za namespaces kwa kutumia wito wa mfumo wa `unshare`. Walakini, mchakato ambao unazindua uundaji wa nafasi mpya ya PID (unaoitwa "mchakato wa unshare") haingii kwenye nafasi mpya; ni mchakato wake wa watoto tu ndio unaingia.
- Kukimbia `%unshare -p /bin/bash%` kuanza `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na mchakato wake wa watoto wako kwenye nafasi ya PID ya awali.
- Mchakato wa kwanza wa watoto wa `/bin/bash` katika nafasi mpya hufanywa kuwa PID 1. Wakati mchakato huu unapoondoka, husababisha kusafisha kwa nafasi hiyo ikiwa hakuna michakato mingine, kwani PID 1 ina jukumu maalum la kuwachukua michakato yatima. Kernel ya Linux kisha itazima ugawaji wa PID katika nafasi hiyo.

2. **Matokeo**:
- Kutoka kwa PID 1 katika nafasi mpya kunasababisha kusafisha kwa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kushindwa kwa kazi ya `alloc_pid` kuweka PID mpya wakati wa kuunda mchakato mpya, na kusababisha kosa la "Haiwezi kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` na `unshare`. Chaguo hili linamfanya `unshare` kugawanya mchakato mpya baada ya kuunda nafasi mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kuwa amri ya `unshare` yenyewe inakuwa PID 1 katika nafasi mpya. Kwa hivyo, `/bin/bash` na mchakato wake wa watoto wako salama ndani ya nafasi hii mpya, kuzuia kutoka kwa kuondoka mapema kwa PID 1 na kuruhusu ugawaji wa PID kawaida.

Kwa kuhakikisha kuwa `unshare` inaendeshwa na bendera ya `-f`, nafasi mpya ya PID inasimamiwa kwa usahihi, kuruhusu `/bin/bash` na michakato yake ya chini kufanya kazi bila kukutana na kosa la ugawaji wa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Angalia ni kwenye namespace gani mchakato wako uko

To check which namespace your process is in, you can use the following command:

Kuangalia ni kwenye namespace gani mchakato wako uko, unaweza kutumia amri ifuatayo:

```bash
cat /proc/$$/mountinfo | grep "ns"
```

This command will display the mount information for your process and filter the output to show only the lines containing "ns". The namespace information will be displayed in the output.

Amri hii itaonyesha habari ya kufunga kwa mchakato wako na kuchuja matokeo ili kuonyesha tu mistari inayohusiana na "ns". Habari ya namespace itaonyeshwa kwenye matokeo.
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Tafuta majina yote ya nafasi za kufunga

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Ingia ndani ya jina nafasi ya Mount

{% endcode %}
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Pia, unaweza **ingia kwenye namespace ya mchakato mwingine ikiwa wewe ni root**. Na huwezi **kuingia** kwenye namespace nyingine **bila kigeuzi** kinachoelekeza kwake (kama vile `/proc/self/ns/mnt`).

Kwa sababu vifungu vipya vinapatikana tu ndani ya namespace, ni muhimu kuzingatia kwamba namespace inaweza kuwa na habari nyeti ambayo inaweza kupatikana tu ndani yake.

### Sakinisha kitu
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
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
