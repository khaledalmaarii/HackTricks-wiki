# PID Namespace

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

Namespace ya PID (Identifier ya Mchakato) ni kipengele katika kernel ya Linux kinachotoa kutengwa kwa mchakato kwa kuwezesha kundi la michakato kuwa na seti yao ya kipekee ya PIDs, tofauti na PIDs katika namespaces nyingine. Hii ni muhimu hasa katika uundaji wa kontena, ambapo kutengwa kwa mchakato ni muhimu kwa usalama na usimamizi wa rasilimali.

Wakati namespace mpya ya PID inaundwa, mchakato wa kwanza katika namespace hiyo unapewa PID 1. Mchakato huu unakuwa mchakato wa "init" wa namespace mpya na unawajibika kwa usimamizi wa michakato mingine ndani ya namespace hiyo. Kila mchakato unaofuata unaoundwa ndani ya namespace hiyo utakuwa na PID ya kipekee ndani ya namespace hiyo, na PIDs hizi zitakuwa huru kutoka kwa PIDs katika namespaces nyingine.

Kutoka kwa mtazamo wa mchakato ndani ya namespace ya PID, unaweza kuona tu michakato mingine katika namespace hiyo hiyo. Haujui kuhusu michakato katika namespaces nyingine, na hauwezi kuingiliana nao kwa kutumia zana za usimamizi wa mchakato za jadi (mfano, `kill`, `wait`, n.k.). Hii inatoa kiwango cha kutengwa ambacho husaidia kuzuia michakato kuingiliana na nyingine.

### How it works:

1. Wakati mchakato mpya unaundwa (mfano, kwa kutumia wito wa mfumo wa `clone()`), mchakato unaweza kupewa namespace mpya au iliyopo. **Ikiwa namespace mpya inaundwa, mchakato unakuwa mchakato wa "init" wa namespace hiyo**.
2. **Kernel** inashikilia **ramani kati ya PIDs katika namespace mpya na PIDs zinazolingana** katika namespace ya mzazi (yaani, namespace ambayo namespace mpya ilianzishwa). Ramani hii **inawawezesha kernel kutafsiri PIDs inapohitajika**, kama vile wakati wa kutuma ishara kati ya michakato katika namespaces tofauti.
3. **Michakato ndani ya namespace ya PID yanaweza kuona na kuingiliana tu na michakato mingine katika namespace hiyo hiyo**. Hawawezi kujua kuhusu michakato katika namespaces nyingine, na PIDs zao ni za kipekee ndani ya namespace yao.
4. Wakati **namespace ya PID inaharibiwa** (mfano, wakati mchakato wa "init" wa namespace unapoondoka), **michakato yote ndani ya namespace hiyo inakatishwa**. Hii inahakikisha kwamba rasilimali zote zinazohusiana na namespace hiyo zinatakaswa ipasavyo.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Hitilafu: bash: fork: Haiwezekani kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, hitilafu inakutana kutokana na jinsi Linux inavyoshughulikia majina mapya ya PID (Kitambulisho cha Mchakato). Maelezo muhimu na suluhisho yameelezwa hapa chini:

1. **Maelezo ya Tatizo**:
- Kernel ya Linux inaruhusu mchakato kuunda majina mapya kwa kutumia wito wa mfumo wa `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa jina jipya la PID (unaorejelewa kama mchakato wa "unshare") hauingii kwenye jina jipya; ni mchakato wake wa watoto pekee wanaingia.
- Kukimbia `%unshare -p /bin/bash%` kunaanzisha `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na mchakato wake wa watoto wako katika jina la awali la PID.
- Mchakato wa kwanza wa mtoto wa `/bin/bash` katika jina jipya huwa PID 1. Wakati mchakato huu unapoondoka, unachochea usafishaji wa jina hilo ikiwa hakuna mchakato mwingine, kwani PID 1 ina jukumu maalum la kupokea mchakato wa yatima. Kernel ya Linux itazima kuteua PID katika jina hilo.

2. **Matokeo**:
- Kuondoka kwa PID 1 katika jina jipya kunasababisha kusafishwa kwa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kazi ya `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, ikitoa hitilafu ya "Haiwezekani kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` pamoja na `unshare`. Chaguo hili linafanya `unshare` kuunda mchakato mpya baada ya kuunda jina jipya la PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kwamba amri ya `unshare` yenyewe inakuwa PID 1 katika jina jipya. `/bin/bash` na mchakato wake wa watoto kisha vinahifadhiwa salama ndani ya jina hili jipya, kuzuia kuondoka mapema kwa PID 1 na kuruhusu kuteua PID kwa kawaida.

Kwa kuhakikisha kwamba `unshare` inakimbia na bendera ya `-f`, jina jipya la PID linatunzwa kwa usahihi, kuruhusu `/bin/bash` na mchakato wake wa chini kufanya kazi bila kukutana na hitilafu ya kugawa kumbukumbu.

</details>

Kwa kuunganisha mfano mpya wa mfumo wa faili wa `/proc` ikiwa utatumia paramu `--mount-proc`, unahakikisha kwamba jina jipya la kuunganisha lina **mtazamo sahihi na wa kutengwa wa taarifa za mchakato maalum kwa jina hilo**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Angalia ni namespace gani mchakato wako uko ndani
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Pata majina yote ya PID

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Kumbuka kwamba matumizi ya root kutoka kwa namespace ya PID ya awali (ya default) yanaweza kuona mchakato wote, hata wale walio katika majina mapya ya PID, ndivyo maana tunaweza kuona majina yote ya PID.

### Ingia ndani ya namespace ya PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Wakati unapoingia ndani ya PID namespace kutoka kwa namespace ya default, bado utaweza kuona mchakato wote. Na mchakato kutoka kwa PID ns utaweza kuona bash mpya kwenye PID ns.

Pia, unaweza tu **kuingia katika namespace ya PID ya mchakato mwingine ikiwa wewe ni root**. Na **huwezi** **kuingia** katika namespace nyingine **bila desktopa** inayotaja hiyo (kama `/proc/self/ns/pid`)

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
</details>
{% endhint %}
