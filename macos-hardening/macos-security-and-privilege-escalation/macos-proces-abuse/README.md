# Uvunjaji wa Mchakato wa macOS

{% hint style="success" %}
Jifunze na zoezi la Uvunjaji wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la Uvunjaji wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Taarifa Msingi za Mchakato

Mchakato ni kipengele cha programu inayotumika, hata hivyo mchakato haufanyi kanuni, hizi ni nyuzi. Kwa hivyo **michakato ni vyombo tu vya nyuzi zinazoendesha** zinazotoa kumbukumbu, maelezo, bandari, ruhusa...

Kihistoria, michakato ilianza ndani ya michakato mingine (isipokuwa PID 1) kwa kuita **`fork`** ambayo ingesababisha nakala kamili ya mchakato wa sasa na kisha **mchakato wa mtoto** kwa ujumla ungeita **`execve`** ili kupakia programu mpya na kuendesha. Kisha, **`vfork`** iliingizwa kufanya mchakato huu kuwa haraka bila kunakili kumbukumbu.\
Kisha **`posix_spawn`** iliingizwa ikichanganya **`vfork`** na **`execve`** katika wito mmoja na kukubali bendera:

* `POSIX_SPAWN_RESETIDS`: Rudisha vitambulisho vya ufanisi kwa vitambulisho halisi
* `POSIX_SPAWN_SETPGROUP`: Weka ushirika wa kikundi cha mchakato
* `POSUX_SPAWN_SETSIGDEF`: Weka tabia ya ishara ya msingi
* `POSIX_SPAWN_SETSIGMASK`: Weka barakoa ya ishara
* `POSIX_SPAWN_SETEXEC`: Endesha katika mchakato huo (kama `execve` na chaguzi zaidi)
* `POSIX_SPAWN_START_SUSPENDED`: Anza kusimamishwa
* `_POSIX_SPAWN_DISABLE_ASLR`: Anza bila ASLR
* `_POSIX_SPAWN_NANO_ALLOCATOR:` Tumia mtoaji wa Nano wa libmalloc
* `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ruhusu `rwx` kwenye sehemu za data
* `POSIX_SPAWN_CLOEXEC_DEFAULT`: Funga maelezo yote ya faili kwenye exec(2) kwa chaguo-msingi
* `_POSIX_SPAWN_HIGH_BITS_ASLR:` Changanya bits za juu za ASLR slide

Zaidi ya hayo, `posix_spawn` inaruhusu kutaja safu ya **`posix_spawnattr`** inayodhibiti baadhi ya vipengele vya mchakato uliozaliwa, na **`posix_spawn_file_actions`** kurekebisha hali ya maelezo.

Mchakato unapokufa hutoa **msimbo wa kurudi kwa mchakato mzazi** (ikiwa mzazi amekufa, mzazi mpya ni PID 1) na ishara `SIGCHLD`. Mzazi lazima apate thamani hii kwa kuita `wait4()` au `waitid()` na mpaka hilo litokee mtoto hubaki katika hali ya zombie ambapo bado iko kwenye orodha lakini haichukui rasilimali.

### PIDs

PIDs, vitambulisho vya mchakato, vinatambua mchakato wa kipekee. Katika XNU **PIDs** ni **bits 64** inayoongezeka kwa mpangilio na **haisongi kamwe** (kuepuka matumizi mabaya).

### Vikundi vya Mchakato, Vikao & Coalitions

**Michakato** inaweza kuwekwa katika **vikundi** ili kuwa rahisi kushughulikia. Kwa mfano, amri katika script ya terminali itakuwa katika kikundi kimoja cha mchakato hivyo ni rahisi **kuwapa ishara pamoja** kwa kutumia kill kwa mfano.\
Pia ni rahisi **kuweka michakato katika vikao**. Wakati mchakato unapoanza kikao (`setsid(2)`), michakato ya watoto huingizwa ndani ya kikao, isipokuwa wanaanza kikao chao wenyewe.

Coalition ni njia nyingine ya kuweka michakato pamoja katika Darwin. Mchakato unapojiunga na muungano inaruhusu kupata rasilimali za dimbwi, kushiriki hesabu au kukabiliana na Jetsam. Coalitions zina majukumu tofauti: Kiongozi, Huduma ya XPC, Ugani.

### Vitambulisho & Personae

Kila mchakato unashikilia **vitambulisho** vinavyo **tambulisha haki zake** katika mfumo. Kila mchakato atakuwa na `uid` ya msingi na `gid` ya msingi (ingawa inaweza kuwa sehemu ya vikundi kadhaa).\
Pia ni rahisi kubadilisha kitambulisho cha mtumiaji na kikundi ikiwa programu ina biti ya `setuid/setgid`.\
Kuna kazi kadhaa za **kuweka vitambulisho vipya**. 

Wito wa mfumo **`persona`** hutoa **seti mbadala** ya **vitambulisho**. Kuchukua persona kunachukulia uid yake, gid na uanachama wa kikundi **kwa pamoja**. Katika [**michocheo**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) inawezekana kupata muundo:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Maelezo Muhimu ya Msingi kuhusu Vitambulisho

1. **Vitambulisho vya POSIX (pthreads):** macOS inasaidia vitambulisho vya POSIX (`pthreads`), ambavyo ni sehemu ya API ya kawaida ya vitambulisho kwa C/C++. Utekelezaji wa pthreads katika macOS unapatikana katika `/usr/lib/system/libsystem_pthread.dylib`, ambayo inatoka kwenye mradi wa `libpthread` uliopo hadharani. Maktaba hii hutoa kazi muhimu za kuunda na kusimamia vitambulisho.
2. **Kuunda Vitambulisho:** Kazi ya `pthread_create()` hutumika kuunda vitambulisho vipya. Kwa ndani, kazi hii huita `bsdthread_create()`, ambayo ni wito wa mfumo wa kiwango cha chini maalum kwa kernel ya XNU (kernel ambayo macOS inategemea). Wito huu wa mfumo huchukua bendera mbalimbali zilizopatikana kutoka `pthread_attr` (sifa) ambazo hufafanua tabia ya kamba, ikiwa ni pamoja na sera za ratiba na ukubwa wa steki.
* **Ukubwa wa Steki wa Kimsingi:** Ukubwa wa kimsingi wa steki kwa vitambulisho vipya ni 512 KB, ambao ni wa kutosha kwa shughuli za kawaida lakini unaweza kurekebishwa kupitia sifa za kamba ikiwa nafasi zaidi au pungufu inahitajika.
3. **Uanzishaji wa Kamba:** Kazi ya `__pthread_init()` ni muhimu wakati wa kuweka kamba, ikichanganua hoja ya `env[]` ili kuchambua mazingira yanayoweza kujumuisha maelezo kuhusu eneo na ukubwa wa steki.

#### Kukomesha Kamba katika macOS

1. **Kukomesha Vitambulisho:** Kamba kawaida hukomeshwa kwa kuita `pthread_exit()`. Kazi hii inaruhusu kamba kufunga, kufanya usafi muhimu na kuruhusu kamba kutuma thamani ya kurudi kwa yeyote anayejumuisha.
2. **Usafi wa Kamba:** Baada ya kuita `pthread_exit()`, kazi ya `pthread_terminate()` inaitwa, ambayo inashughulikia kuondoa miundo yote ya kamba inayohusiana. Inaachilia bandari za kamba za Mach (Mach ni mfumo wa mawasiliano katika kernel ya XNU) na kuita `bsdthread_terminate`, wito wa mfumo unaondoa miundo katika kiwango cha kernel inayohusiana na kamba.

#### Mbinu za Uga wa Synchronization

Ili kusimamia upatikanaji wa rasilimali zinazoshirikishwa na kuepuka hali za mbio, macOS hutoa vipengele kadhaa vya uga wa usawazishaji. Hivi ni muhimu katika mazingira ya vitambulisho vingi kuhakikisha uadilifu wa data na utulivu wa mfumo:

1. **Mutexes:**
* **Mutex ya Kawaida (Sahihi: 0x4D555458):** Mutex ya kawaida yenye kumbukumbu ya 60 baiti (baiti 56 kwa mutex na baiti 4 kwa sahihi).
* **Mutex ya Haraka (Sahihi: 0x4d55545A):** Kama mutex ya kawaida lakini imeboreshwa kwa operesheni za haraka, pia ukubwa wa 60 baiti.
2. **Hali za Mazingira:**
* Hutumiwa kusubiri hali fulani kutokea, na ukubwa wa 44 baiti (baiti 40 pamoja na sahihi ya baiti 4).
* **Sifa za Hali ya Mazingira (Sahihi: 0x434e4441):** Sifa za usanidi kwa hali za mazingira, ukubwa wa 12 baiti.
3. **Kigezo cha Mara Moja (Sahihi: 0x4f4e4345):**
* Huhakikisha kuwa kipande cha nambari ya kuanzisha kinatekelezwa mara moja tu. Ukubwa wake ni 12 baiti.
4. **Kufunga Kusoma-Kuandika:**
* Inaruhusu wasomaji wengi au mwandishi mmoja kwa wakati, ikirahisisha upatikanaji wa ufanisi wa data zinazoshirikishwa.
* **Kufunga Kusoma-Kuandika (Sahihi: 0x52574c4b):** Ukubwa wa 196 baiti.
* **Sifa za Kufunga Kusoma-Kuandika (Sahihi: 0x52574c41):** Sifa za kufunga kusoma-kuandika, ukubwa wa 20 baiti.

{% hint style="success" %}
Baiti 4 za mwisho za vitu hivyo hutumiwa kugundua kujaa kupita kiasi.
{% endhint %}

### Vitambulisho vya Mazingira ya Kamba (TLV)

**Vitambulisho vya Mazingira ya Kamba (TLV)** katika muktadha wa faili za Mach-O (muundo wa kutekelezeka katika macOS) hutumika kutangaza vitu ambavyo ni maalum kwa **kila kamba** katika maombi yenye vitambulisho vingi. Hii inahakikisha kuwa kila kamba ina mfano wake wa kipekee wa kipengee, ikitoa njia ya kuepuka migogoro na kudumisha uadilifu wa data bila kuhitaji vipengele vya usawazishaji wazi kama mutexes.

Katika C na lugha zinazohusiana, unaweza kutangaza kipengee cha kamba la eneo kwa kutumia neno la **`__thread`**. Hapa ndivyo inavyofanya kazi katika mfano wako:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Hii sehemu inadefine `tlv_var` kama variable ya thread-local. Kila thread inayotumia code hii itakuwa na `tlv_var` yake, na mabadiliko ambayo thread moja inafanya kwa `tlv_var` hayataathiri `tlv_var` kwenye thread nyingine.

Katika Mach-O binary, data inayohusiana na variables za thread local imepangwa katika sehemu maalum:

* **`__DATA.__thread_vars`**: Sehemu hii ina metadata kuhusu variables za thread-local, kama aina zao na hali ya kuanzisha.
* **`__DATA.__thread_bss`**: Sehemu hii hutumika kwa variables za thread-local ambazo hazijaanzishwa wazi. Ni sehemu ya kumbukumbu iliyowekwa kando kwa data iliyoanzishwa na sifuri.

Mach-O pia hutoa API maalum inayoitwa **`tlv_atexit`** kusimamia variables za thread-local wakati thread inamaliza. API hii inaruhusu **kujiandikisha kwa destructors**—functions maalum ambazo hufuta data za thread-local wakati thread inamaliza.

### Vipaumbele vya Threading

Kuelewa vipaumbele vya thread kunahusisha kuangalia jinsi mfumo wa uendeshaji unavyoamua ni thread zipi zitakazoendeshwa na lini. Uamuzi huu unaathiriwa na kiwango cha kipaumbele kilichopewa kila thread. Katika macOS na mifumo inayofanana na Unix, hili linashughulikiwa kwa kutumia dhana kama `nice`, `renice`, na darasa la Quality of Service (QoS).

#### Nice na Renice

1. **Nice:**
* Thamani ya `nice` ya mchakato ni nambari inayoathiri kipaumbele chake. Kila mchakato una thamani ya nice inayotoka -20 (kipaumbele cha juu zaidi) hadi 19 (kipaumbele cha chini zaidi). Thamani ya nice ya msingi wakati mchakato unavyoundwa kawaida ni 0.
* Thamani ya nice ya chini (karibu na -20) inafanya mchakato kuwa "binafsi zaidi," ikimpa muda zaidi wa CPU ikilinganishwa na michakato mingine yenye thamani za nice za juu.
2. **Renice:**
* `renice` ni amri inayotumika kubadilisha thamani ya nice ya mchakato unaoendeshwa tayari. Hii inaweza kutumika kurekebisha kipaumbele cha michakato kwa muda, ikiongeza au kupunguza mgawo wao wa muda wa CPU kulingana na thamani mpya za nice.
* Kwa mfano, ikiwa mchakato unahitaji rasilimali za CPU zaidi kwa muda, unaweza kupunguza thamani yake ya nice kwa kutumia `renice`.

#### Darasa la Quality of Service (QoS)

Darasa za QoS ni njia ya kisasa zaidi ya kushughulikia vipaumbele vya thread, hasa katika mifumo kama macOS inayounga mkono **Grand Central Dispatch (GCD)**. Darasa za QoS huruhusu watengenezaji **kutambua** kazi katika viwango tofauti kulingana na umuhimu au dharura yao. macOS inasimamia vipaumbele vya thread moja kwa moja kulingana na darasa za QoS hizi:

1. **User Interactive:**
* Darasa hili ni kwa kazi ambazo kwa sasa zinaingiliana na mtumiaji au zinahitaji matokeo ya haraka ili kutoa uzoefu mzuri kwa mtumiaji. Kazi hizi hupewa kipaumbele cha juu ili kudumisha majibu ya haraka ya interface (k.m., michoro au usindikaji wa matukio).
2. **User Initiated:**
* Kazi ambazo mtumiaji anaanzisha na anatarajia matokeo ya haraka, kama vile kufungua hati au kubonyeza kitufe kinachohitaji mahesabu. Hizi ni kipaumbele cha juu lakini chini ya user interactive.
3. **Utility:**
* Kazi hizi ni za muda mrefu na kawaida huonyesha kiashiria cha maendeleo (k.m., kupakua faili, kuingiza data). Zina kipaumbele cha chini kuliko kazi zilizoanzishwa na mtumiaji na hazihitaji kumalizika mara moja.
4. **Background:**
* Darasa hili ni kwa kazi zinazofanya kazi nyuma na hazionekani na mtumiaji. Hizi zinaweza kuwa kazi kama vile kutengeneza orodha, kusawazisha, au kuhifadhi nakala rudufu. Zina kipaumbele cha chini kabisa na athari ndogo kwa utendaji wa mfumo.

Kwa kutumia darasa za QoS, watengenezaji hawahitaji kusimamia nambari sahihi za vipaumbele bali badala yake wanazingatia asili ya kazi, na mfumo unaoptimiza rasilimali za CPU kulingana na hilo.

Zaidi ya hayo, kuna **sera tofauti za ratiba za thread** ambazo hufanya mwendeshaji kuweka seti ya vigezo vya ratiba ambavyo mwendeshaji atazingatia. Hii inaweza kufanywa kwa kutumia `thread_policy_[set/get]`. Hii inaweza kuwa muhimu katika mashambulizi ya hali ya mbio.

## Uvunjaji wa Mchakato wa MacOS

MacOS, kama mifumo mingine yoyote ya uendeshaji, hutoa njia na mbinu mbalimbali za **mchakato wa kuingiliana, kuwasiliana, na kushiriki data**. Ingawa njia hizi ni muhimu kwa utendaji mzuri wa mfumo, zinaweza pia kutumiwa vibaya na wahalifu wa mtandao kufanya **shughuli za uovu**.

### Uvamizi wa Maktaba

Uvamizi wa Maktaba ni mbinu ambapo muhusika wa uhalifu wa kimtandao **anashinikiza mchakato kusoma maktaba yenye nia mbaya**. Mara baada ya kuingizwa, maktaba inaendeshwa katika muktadha wa mchakato lengwa, ikimpa muhusika wa uhalifu upatikanaji sawa na ruhusa kama mchakato.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Kufunga Kazi

Kufunga Kazi inahusisha **kuingilia simu za kazi** au ujumbe ndani ya nambari ya programu. Kwa kufunga kazi, muhusika wa uhalifu anaweza **kurekebisha tabia** ya mchakato, kuchunguza data nyeti, au hata kupata udhibiti wa mtiririko wa utekelezaji.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md](macos-function-hooking.md)
{% endcontent-ref %}

### Mawasiliano kati ya Mchakato

Mawasiliano kati ya Mchakato (IPC) inahusu njia tofauti ambazo michakato tofauti **hushiriki na kubadilishana data**. Ingawa IPC ni muhimu kwa programu nyingi halali, inaweza pia kutumiwa vibaya kuvunja upweke wa mchakato, kuvuja taarifa nyeti, au kufanya vitendo visivyoruhusiwa.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Uvamizi wa Programu za Electron

Programu za Electron zilizoendeshwa na mazingira maalum ya mazingira zinaweza kuwa hatarini kwa uvamizi wa mchakato:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Uvamizi wa Chromium

Inawezekana kutumia bendera `--load-extension` na `--use-fake-ui-for-media-stream` kufanya **shambulio la mtu katikati ya kivinjari** kuruhusu kuiba kubonyeza, trafiki, vidakuzi, kuingiza skripti kwenye kurasa...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### NIB Chafu

Faili za NIB **hutambua vipengele vya interface ya mtumiaji (UI)** na mwingiliano wao ndani ya programu. Hata hivyo, wanaweza **kutekeleza amri za kiholela** na **Gatekeeper haisimamishi** programu iliyotekelezwa tayari isitekelezwe ikiwa **faili ya NIB imebadilishwa**. Kwa hivyo, zinaweza kutumika kufanya programu za kiholela kutekeleza amri za kiholela:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Uvamizi wa Programu za Java

Inawezekana kutumia uwezo fulani wa java (kama **`_JAVA_OPTS`** env variable) kufanya programu ya java itekeleze **mambo/kamandi za kiholela**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Uvamizi wa Programu za .Net

Inawezekana kuingiza nambari kwenye programu za .Net kwa **kutumia vibaya kazi ya uchunguzi wa .Net** (ambayo haijalindwa na kinga za macOS kama uimarishaji wa wakati wa utekelezaji).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Uvamizi wa Perl

Angalia chaguzi tofauti za kufanya scripti ya Perl itekeleze mambo ya kiholela katika:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Uvamizi wa Ruby

Pia inawezekana kutumia mazingira ya ruby env kufanya skripti za kiholela zitekeleze mambo ya kiholela:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}
### Kuingiza Python

Ikiwa mazingira ya **`PYTHONINSPECT`** yanawekwa, mchakato wa python utaingia kwenye cli ya python mara tu itakapomaliza. Pia ni pamoja na kutumia **`PYTHONSTARTUP`** kuashiria skripti ya python ya kutekeleza mwanzoni mwa kikao cha mwingiliano.\
Hata hivyo, kumbuka kwamba skripti ya **`PYTHONSTARTUP`** haitatekelezwa wakati **`PYTHONINSPECT`** inaunda kikao cha mwingiliano.

Mazingira mengine kama vile **`PYTHONPATH`** na **`PYTHONHOME`** pia yanaweza kuwa na manufaa kufanya amri ya python itekeleze nambari ya kupindukia.

Tambua kwamba programu zilizoundwa na **`pyinstaller`** hazitatumia mazingira haya hata kama zinakimbia kutumia python iliyomo.

{% hint style="danger" %}
Kwa ujumla, sikuweza kupata njia ya kufanya python itekeleze nambari ya kupindukia kwa kutumia mazingira ya mazingira.\
Hata hivyo, wengi wa watu hufunga pyhton kwa kutumia **Hombrew**, ambayo itaiweka pyhton katika **eneo linaloweza kuandikwa** kwa mtumiaji wa kawaida wa msimamizi. Unaweza kuiteka na kitu kama:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Hata **root** atakimbia nambari hii wakati wa kukimbia python.

## Uchunguzi

### Kinga

[**Kinga**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) ni programu huru ambayo inaweza **kugundua na kuzuia vitendo vya kuingiza mchakato**:

* Kutumia **Mazingira ya Mazingira**: Itaangalia uwepo wa mojawapo ya mazingira yafuatayo: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** na **`ELECTRON_RUN_AS_NODE`**
* Kutumia simu za **`task_for_pid`**: Kugundua wakati mchakato mmoja unataka kupata **bandari ya kazi ya mwingine** ambayo inaruhusu kuingiza nambari katika mchakato.
* **Parameta za programu za Electron**: Mtu anaweza kutumia **`--inspect`**, **`--inspect-brk`** na **`--remote-debugging-port`** hoja ya mstari wa amri kuanza programu ya Electron katika hali ya kurekebisha, na hivyo kuingiza nambari kwake.
* Kutumia **viungo vya alama** au **viungo vya ngumu**: Kawaida unyanyasaji wa kawaida ni kuweka kiungo na **ruhusa zetu za mtumiaji**, na **kuielekeza kwenye eneo lenye ruhusa kubwa**. Uchunguzi ni rahisi sana kwa viungo vya ngumu na viungo vya alama. Ikiwa mchakato unaounda kiungo una **kiwango tofauti cha ruhusa** kuliko faili ya lengo, tunatuma **onyo**. Kwa bahati mbaya katika kesi ya viungo vya alama, kuzuia haiwezekani, kwani hatuna habari kuhusu marudio ya kiungo kabla ya uumbaji. Hii ni kizuizi cha mfumo wa EndpointSecuriy wa Apple.

### Simu zilizofanywa na michakato mingine

Katika [**chapisho hili la blogi**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kupata jinsi inavyowezekana kutumia kazi ya **`task_name_for_pid`** kupata habari kuhusu **michakato inayoingiza nambari katika mchakato** na kisha kupata habari kuhusu mchakato mwingine huo.

Tafadhali kumbuka kwamba ili kupiga simu kazi hiyo unahitaji kuwa **uid sawa** na yule anayekimbia mchakato au **root** (na inarudi habari kuhusu mchakato, sio njia ya kuingiza nambari).

## Marejeo

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

{% hint style="success" %}
Jifunze & zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
