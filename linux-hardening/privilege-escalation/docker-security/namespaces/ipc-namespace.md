# IPC Namespace

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}

## Basic Information

IPC (Inter-Process Communication) namespace ni kipengele cha kernel ya Linux kinachotoa **kujitoa** kwa vitu vya System V IPC, kama vile foleni za ujumbe, sehemu za kumbukumbu zinazoshirikiwa, na semaphores. Kujitoa huku kunahakikisha kwamba michakato katika **namespaces tofauti za IPC haiwezi kufikia moja kwa moja au kubadilisha vitu vya IPC vya kila mmoja**, na kutoa safu ya ziada ya usalama na faragha kati ya vikundi vya michakato.

### How it works:

1. Wakati namespace mpya ya IPC inaundwa, inaanza na **seti iliyojitenga kabisa ya vitu vya System V IPC**. Hii inamaanisha kwamba michakato inayofanya kazi katika namespace mpya ya IPC haiwezi kufikia au kuingilia vitu vya IPC katika namespaces nyingine au mfumo wa mwenyeji kwa default.
2. Vitu vya IPC vilivyoundwa ndani ya namespace vinonekana na **vinapatikana tu kwa michakato ndani ya namespace hiyo**. Kila kitu cha IPC kinatambulishwa kwa funguo ya kipekee ndani ya namespace yake. Ingawa funguo inaweza kuwa sawa katika namespaces tofauti, vitu wenyewe vimejitengea na haviwezi kufikiwa kati ya namespaces.
3. Michakato inaweza kuhamia kati ya namespaces kwa kutumia wito wa mfumo wa `setns()` au kuunda namespaces mpya kwa kutumia wito wa mfumo wa `unshare()` au `clone()` na bendera ya `CLONE_NEWIPC`. Wakati mchakato unahamia kwenye namespace mpya au kuunda moja, utaanza kutumia vitu vya IPC vinavyohusishwa na namespace hiyo.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Kwa kuunganisha mfano mpya wa mfumo wa `/proc` ikiwa unatumia param `--mount-proc`, unahakikisha kwamba nafasi mpya ya kuunganisha ina **mtazamo sahihi na uliojitegemea wa taarifa za mchakato zinazohusiana na nafasi hiyo**.

<details>

<summary>Kosa: bash: fork: Haiwezekani kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, kosa linakutana kutokana na jinsi Linux inavyoshughulikia nafasi mpya za PID (Kitambulisho cha Mchakato). Maelezo muhimu na suluhisho yameelezwa hapa chini:

1. **Maelezo ya Tatizo**:
- Kernel ya Linux inaruhusu mchakato kuunda nafasi mpya kwa kutumia wito wa mfumo wa `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa nafasi mpya ya PID (inayojulikana kama mchakato wa "unshare") hauingii katika nafasi mpya; ni watoto wake tu ndio wanaingia.
- Kuendesha `%unshare -p /bin/bash%` kunaanzisha `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na watoto wake wako katika nafasi ya awali ya PID.
- Mchakato wa kwanza wa mtoto wa `/bin/bash` katika nafasi mpya unakuwa PID 1. Wakati mchakato huu unapoondoka, unachochea usafishaji wa nafasi hiyo ikiwa hakuna mchakato mwingine, kwani PID 1 ina jukumu maalum la kupokea mchakato wa yatima. Kernel ya Linux itazima ugawaji wa PID katika nafasi hiyo.

2. **Matokeo**:
- Kuondoka kwa PID 1 katika nafasi mpya kunasababisha kusafishwa kwa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kazi ya `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, ikitoa kosa la "Haiwezekani kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` pamoja na `unshare`. Chaguo hili linafanya `unshare` kuunda mchakato mpya baada ya kuunda nafasi mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kwamba amri ya `unshare` yenyewe inakuwa PID 1 katika nafasi mpya. `/bin/bash` na watoto wake wanakuwa salama ndani ya nafasi hii mpya, kuzuia kuondoka mapema kwa PID 1 na kuruhusu ugawaji wa kawaida wa PID.

Kwa kuhakikisha kwamba `unshare` inatekelezwa na bendera ya `-f`, nafasi mpya ya PID inatunzwa ipasavyo, ikiruhusu `/bin/bash` na mchakato wake wa chini kufanya kazi bila kukutana na kosa la kugawa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Angalia ni namespace ipi mchakato wako uko ndani yake
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Pata majina yote ya IPC

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Ingia ndani ya IPC namespace
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Pia, unaweza tu **kuingia katika namespace ya mchakato mwingine ikiwa wewe ni root**. Na huwezi **kuingia** katika namespace nyingine **bila deskteta** inayorejelea hiyo (kama `/proc/self/ns/net`).

### Create IPC object
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
## References
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)


{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
</details>
{% endhint %}
