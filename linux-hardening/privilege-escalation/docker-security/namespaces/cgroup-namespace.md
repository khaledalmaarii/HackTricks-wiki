# CGroup Namespace

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

## Basic Information

Cgroup namespace ni kipengele cha kernel ya Linux ambacho kinatoa **kujitengea kwa hierarchies za cgroup kwa michakato inayofanya kazi ndani ya namespace**. Cgroups, kifupi kwa **control groups**, ni kipengele cha kernel kinachoruhusu kupanga michakato katika makundi ya kihierarkia ili kudhibiti na kutekeleza **mipaka kwenye rasilimali za mfumo** kama CPU, kumbukumbu, na I/O.

Ingawa cgroup namespaces si aina tofauti ya namespace kama zile tulizozijadili awali (PID, mount, network, n.k.), zinahusiana na dhana ya kujitengea kwa namespace. **Cgroup namespaces zinafanya virtualize mtazamo wa hierarchi ya cgroup**, ili michakato inayofanya kazi ndani ya cgroup namespace iwe na mtazamo tofauti wa hierarchi ikilinganishwa na michakato inayofanya kazi kwenye mwenyeji au namespaces nyingine.

### How it works:

1. Wakati cgroup namespace mpya inaundwa, **inaanza na mtazamo wa hierarchi ya cgroup kulingana na cgroup ya mchakato unaounda**. Hii inamaanisha kwamba michakato inayofanya kazi katika cgroup namespace mpya itaona tu sehemu ya hierarchi ya cgroup yote, iliyopunguzia kwenye cgroup subtree iliyoanzishwa kwenye cgroup ya mchakato unaounda.
2. Michakato ndani ya cgroup namespace itakuwa **inaona cgroup yao wenyewe kama mzizi wa hierarchi**. Hii inamaanisha kwamba, kutoka mtazamo wa michakato ndani ya namespace, cgroup yao wenyewe inaonekana kama mzizi, na hawawezi kuona au kufikia cgroups nje ya subtree yao wenyewe.
3. Cgroup namespaces hazitoi moja kwa moja kujitengea kwa rasilimali; **zinatoa tu kujitengea kwa mtazamo wa hierarchi ya cgroup**. **Udhibiti wa rasilimali na kujitengea bado unatekelezwa na cgroup** subsystems (mfano, cpu, kumbukumbu, n.k.) wenyewe.

Kwa maelezo zaidi kuhusu CGroups angalia:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Kwa kuunganisha mfano mpya wa mfumo wa `/proc` ikiwa unatumia param `--mount-proc`, unahakikisha kwamba nafasi mpya ya kuunganisha ina **mtazamo sahihi na wa kutengwa wa taarifa za mchakato maalum kwa nafasi hiyo**.

<details>

<summary>Hitilafu: bash: fork: Haiwezekani kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, hitilafu inakutana kutokana na jinsi Linux inavyoshughulikia nafasi mpya za PID (Kitambulisho cha Mchakato). Maelezo muhimu na suluhisho yameelezwa hapa chini:

1. **Maelezo ya Tatizo**:
- Kernel ya Linux inaruhusu mchakato kuunda nafasi mpya kwa kutumia wito wa mfumo wa `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa nafasi mpya ya PID (inayojulikana kama mchakato wa "unshare") hauingii kwenye nafasi mpya; ni mchakato zake za watoto pekee ndizo zinaingia.
- Kukimbia `%unshare -p /bin/bash%` kunaanzisha `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na mchakato zake za watoto ziko katika nafasi ya awali ya PID.
- Mchakato wa kwanza wa mtoto wa `/bin/bash` katika nafasi mpya inakuwa PID 1. Wakati mchakato huu unapoondoka, unachochea usafishaji wa nafasi hiyo ikiwa hakuna mchakato mwingine, kwani PID 1 ina jukumu maalum la kupokea mchakato wa yatima. Kernel ya Linux itazima kisha ugawaji wa PID katika nafasi hiyo.

2. **Matokeo**:
- Kuondoka kwa PID 1 katika nafasi mpya kunasababisha usafishaji wa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kazi ya `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, ikitoa hitilafu ya "Haiwezekani kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` pamoja na `unshare`. Chaguo hili linafanya `unshare` kuunda mchakato mpya baada ya kuunda nafasi mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kwamba amri ya `unshare` yenyewe inakuwa PID 1 katika nafasi mpya. `/bin/bash` na mchakato zake za watoto kisha zinahifadhiwa salama ndani ya nafasi hii mpya, kuzuia kuondoka mapema kwa PID 1 na kuruhusu ugawaji wa PID wa kawaida.

Kwa kuhakikisha kwamba `unshare` inakimbia na bendera ya `-f`, nafasi mpya ya PID inatunzwa kwa usahihi, ikiruhusu `/bin/bash` na mchakato zake za chini kufanya kazi bila kukutana na hitilafu ya ugawaji wa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Angalia ni namespace ipi mchakato wako uko ndani yake
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Pata majina yote ya CGroup

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Ingia ndani ya cgroup namespace
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Pia, unaweza tu **kuingia katika nafasi nyingine ya mchakato ikiwa wewe ni root**. Na huwezi **kuingia** katika nafasi nyingine **bila desktopa** inayorejelea hiyo (kama `/proc/self/ns/cgroup`).

## References
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

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
