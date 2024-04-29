# Uvunjaji wa Mchakato wa macOS

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Taarifa Msingi za Mchakato

Mchakato ni kipindi cha kutekelezwa kwa faili, hata hivyo mchakato haufanyi kanuni, hizi ni nyuzi. Kwa hivyo **michakato ni vyombo tu vya nyuzi zinazoendeshwa** zinazotoa kumbukumbu, maelezo, bandari, ruhusa...

Kihistoria, michakato ilianza ndani ya michakato mingine (isipokuwa PID 1) kwa kuita **`fork`** ambayo ingesababisha nakala kamili ya mchakato wa sasa na kisha **mchakato wa mtoto** kwa ujumla ungeita **`execve`** kusoma programu mpya na kuendesha. Kisha, **`vfork`** iliingizwa kufanya mchakato huu kuwa haraka bila kunakili kumbukumbu.\
Kisha **`posix_spawn`** iliingizwa ikichanganya **`vfork`** na **`execve`** katika wito mmoja na kukubali bendera:

* `POSIX_SPAWN_RESETIDS`: Rudisha vitambulisho vya ufanisi kwa vitambulisho halisi
* `POSIX_SPAWN_SETPGROUP`: Weka ushirika wa kikundi cha mchakato
* `POSUX_SPAWN_SETSIGDEF`: Weka tabia ya ishara ya msingi
* `POSIX_SPAWN_SETSIGMASK`: Weka barakoa ya ishara
* `POSIX_SPAWN_SETEXEC`: Endesha katika mchakato huo (kama `execve` na chaguzi zaidi)
* `POSIX_SPAWN_START_SUSPENDED`: Anza kusimamishwa
* `_POSIX_SPAWN_DISABLE_ASLR`: Anza bila ASLR
* `_POSIX_SPAWN_NANO_ALLOCATOR:` Tumia mpangilio wa Nano wa libmalloc
* `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ruhusu `rwx` kwenye sehemu za data
* `POSIX_SPAWN_CLOEXEC_DEFAULT`: Funga maelezo yote ya faili kwenye exec(2) kwa chaguo-msingi
* `_POSIX_SPAWN_HIGH_BITS_ASLR:` Changanya bits za juu za ASLR slide

Zaidi ya hayo, `posix_spawn` inaruhusu kutaja safu ya **`posix_spawnattr`** inayodhibiti baadhi ya vipengele vya mchakato uliozaliwa, na **`posix_spawn_file_actions`** kurekebisha hali ya maelezo.

Mchakato unapokufa hutoa **msimbo wa kurudi kwa mchakato mzazi** (ikiwa mzazi amekufa, mzazi mpya ni PID 1) na ishara `SIGCHLD`. Mzazi lazima apate thamani hii kwa kuita `wait4()` au `waitid()` na mpaka hilo litokee mtoto hubaki katika hali ya zombie ambapo bado iko kwenye orodha lakini haichukui rasilimali.

### PIDs

PIDs, vitambulisho vya mchakato, vinatambua mchakato wa kipekee. Katika XNU **PIDs** ni **bits 64** zinazoongezeka kwa mpangilio na **hazijarudi nyuma kamwe** (kuepuka matumizi mabaya).

### Vikundi vya Mchakato, Vikao & Coalitions

**Michakato** inaweza kuwekwa katika **vikundi** ili kuwa rahisi kushughulikia. Kwa mfano, amri katika script ya terminal itakuwa katika kikundi kimoja cha mchakato hivyo ni rahisi **kuwapa ishara pamoja** kwa kutumia kill kwa mfano.\
Pia ni rahisi **kuweka michakato katika vikao**. Wakati mchakato unapoanza kikao (`setsid(2)`), michakato ya watoto huingizwa ndani ya kikao, isipokuwa wanaanza vikao vyao wenyewe.

Coalition ni njia nyingine ya kuweka michakato pamoja katika Darwin. Mchakato unapojiunga na muungano inaruhusu kupata rasilimali za dimbwi, kushiriki katika akaunti au kukabiliana na Jetsam. Coalitions zina majukumu tofauti: Kiongozi, Huduma ya XPC, Ugani.

### Vitambulisho & Personae

Kila mchakato unashikilia **vitambulisho** vinavyo **tambulisha haki zake** katika mfumo. Kila mchakato atakuwa na `uid` ya msingi na `gid` moja (ingawa inaweza kuwa sehemu ya vikundi kadhaa).\
Pia ni rahisi kubadilisha kitambulisho cha mtumiaji na kikundi ikiwa faili ina biti ya `setuid/setgid`.\
Kuna kazi kadhaa za **kuweka vitambulisho vipya**.

Wito wa mfumo **`persona`** hutoa **seti mbadala** ya **vitambulisho**. Kuchukua persona kunachukulia uid yake, gid na uanachama wa kikundi **kwa pamoja**. Katika [**msimbo wa chanzo**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) inawezekana kupata muundo:
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
## Taarifa Msingi za Vitambulisho

1. **Vitambulisho vya POSIX (pthreads):** macOS inasaidia vitambulisho vya POSIX (`pthreads`), ambavyo ni sehemu ya API ya kawaida ya vitambulisho kwa C/C++. Utekelezaji wa pthreads katika macOS unapatikana katika `/usr/lib/system/libsystem_pthread.dylib`, ambayo inatoka kwenye mradi wa `libpthread` uliopo hadharani. Maktaba hii hutoa kazi muhimu za kuunda na kusimamia vitambulisho.
2. **Kuunda Vitambulisho:** Kazi ya `pthread_create()` hutumika kuunda vitambulisho vipya. Kwa ndani, kazi hii huita `bsdthread_create()`, ambayo ni wito wa mfumo wa kiwango cha chini maalum kwa kernel ya XNU (kernel ambayo macOS inategemea). Wito huu wa mfumo huchukua bendera mbalimbali zilizopatikana kutoka `pthread_attr` (sifa) ambazo hufafanua tabia ya kamba, ikiwa ni pamoja na sera za ratiba na ukubwa wa steki.
* **Ukubwa wa Steki wa Kawaida:** Ukubwa wa steki wa kawaida kwa vitambulisho vipya ni 512 KB, ambao ni wa kutosha kwa shughuli za kawaida lakini unaweza kurekebishwa kupitia sifa za kamba ikiwa nafasi zaidi au chache inahitajika.
3. **Uanzishaji wa Kamba:** Kazi ya `__pthread_init()` ni muhimu wakati wa kuweka kamba, ikichanganua hoja za `env[]` ambazo zinaweza kujumuisha maelezo kuhusu eneo na ukubwa wa steki.

#### Kukomesha Kamba katika macOS

1. **Kukomesha Vitambulisho:** Kamba kawaida hukomeshwa kwa kuita `pthread_exit()`. Kazi hii inaruhusu kamba kufunga kwa usafi, kufanya usafi muhimu na kuruhusu kamba kutuma thamani ya kurudi kwa yeyote anayejumuisha.
2. **Usafi wa Kamba:** Baada ya kuita `pthread_exit()`, kazi ya `pthread_terminate()` inaitwa, ambayo inashughulikia kuondoa miundo yote ya kamba inayohusiana. Inaachilia bandari za kamba za Mach (Mach ni mfumo wa mawasiliano katika kernel ya XNU) na kuita `bsdthread_terminate`, wito wa mfumo ambao unatoa miundo katika kiwango cha kernel inayohusiana na kamba.

#### Mbinu za Uga wa Synchronization

Ili kusimamia upatikanaji wa rasilimali zinazoshirikishwa na kuepuka hali za mbio, macOS hutoa vifaa kadhaa vya kusawazisha. Hivi ni muhimu katika mazingira ya multi-threading kuhakikisha uadilifu wa data na utulivu wa mfumo:

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

### Vitambulisho vya Mtaalam wa Kamba (TLV)

**Vitambulisho vya Mtaalam wa Kamba (TLV)** katika muktadha wa faili za Mach-O (muundo wa kutekelezeka katika macOS) hutumika kutangaza vitambulisho ambavyo ni maalum kwa **kila kamba** katika maombi yenye nyuzi nyingi. Hii inahakikisha kuwa kila kamba ina mfano wake wa kipekee wa kamba, ikitoa njia ya kuepuka migogoro na kudumisha uadilifu wa data bila kuhitaji vifaa vya usawazishaji wazi kama mutexes.

Katika C na lugha zinazohusiana, unaweza kutangaza kigezo cha mtaalam wa kamba ukitumia neno la **`__thread`**. Hapa ndipo jinsi inavyofanya kazi katika mfano wako:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Hii sehemu inadefini `tlv_var` kama kipengele cha mnyororo wa wateja. Kila mnyororo unaoendesha nambari hii utakuwa na `tlv_var` yake, na mabadiliko ambayo mnyororo mmoja anafanya kwa `tlv_var` hayataathiri `tlv_var` katika mnyororo mwingine.

Katika Mach-O binary, data inayohusiana na mienendo ya wateja wa ndani ya mnyororo imepangwa katika sehemu maalum:

- **`__DATA.__thread_vars`**: Sehemu hii ina metadata kuhusu mienendo ya wateja wa ndani ya mnyororo, kama aina zao na hali ya kuanzisha.
- **`__DATA.__thread_bss`**: Sehemu hii hutumika kwa mienendo ya wateja wa ndani ya mnyororo ambao haujaanzishwa wazi. Ni sehemu ya kumbukumbu iliyowekwa kando kwa data iliyoanzishwa na sifuri.

Mach-O pia hutoa API maalum inayoitwa **`tlv_atexit`** kusimamia mienendo ya wateja wa ndani ya mnyororo wakati mnyororo unapoondoka. API hii inaruhusu **kujiandikisha kwa wabomoaji**—kazi maalum ambazo hufuta data ya wateja wa ndani ya mnyororo wakati mnyororo unapomaliza.

### Vipaumbele vya Mienendo

Kuelewa vipaumbele vya mienendo kunahusisha kutazama jinsi mfumo wa uendeshaji unavyoamua ni mienendo gani itakayoendeshwa na lini. Uamuzi huu unaathiriwa na kiwango cha kipaumbele kilichopewa kila mnyororo. Katika macOS na mifumo inayofanana na Unix, hili linashughulikiwa kwa kutumia dhana kama `nice`, `renice`, na darasa la Ubora wa Huduma (QoS).

#### Nice na Renice

1. **Nice:**
   - Thamani ya `nice` ya mchakato ni nambari inayoathiri kipaumbele chake. Kila mchakato una thamani ya nice inayotoka -20 (kipaumbele cha juu zaidi) hadi 19 (kipaumbele cha chini zaidi). Thamani ya nice ya msingi wakati mchakato unapoanzishwa kawaida ni 0.
   - Thamani ya nice ya chini (karibu na -20) inafanya mchakato kuwa "binafsi" zaidi, ikimpa muda zaidi wa CPU ikilinganishwa na michakato mingine yenye thamani za nice za juu.
2. **Renice:**
   - `renice` ni amri inayotumika kubadilisha thamani ya nice ya mchakato uliokuwa ukiendeshwa tayari. Hii inaweza kutumika kurekebisha kipaumbele cha michakato kwa muda, ikiongeza au kupunguza mgawo wao wa muda wa CPU kulingana na thamani mpya za nice.
   - Kwa mfano, ikiwa mchakato unahitaji rasilimali zaidi za CPU kwa muda, unaweza kupunguza thamani yake ya nice kwa kutumia `renice`.

#### Darasa la Ubora wa Huduma (QoS)

Darasa za QoS ni njia ya kisasa zaidi ya kushughulikia vipaumbele vya mienendo, hasa katika mifumo kama macOS ambayo inasaidia **Grand Central Dispatch (GCD)**. Darasa za QoS huruhusu watengenezaji **kutambua** kazi katika viwango tofauti kulingana na umuhimu au dharura yao. macOS inasimamia vipaumbele vya mienendo kiotomatiki kulingana na darasa za QoS hizi:

1. **Mwingiliano wa Mtumiaji:**
   - Darasa hili ni kwa kazi ambazo kwa sasa zinaingiliana na mtumiaji au zinahitaji matokeo ya haraka ili kutoa uzoefu mzuri wa mtumiaji. Kazi hizi hupewa kipaumbele cha juu ili kuweka kiolesura cha mtumiaji kikiwa na majibu (k.m., michoro za kuburudisha au usindikaji wa matukio).
2. **Mtumiaji Anayeanzisha:**
   - Kazi ambazo mtumiaji anaanzisha na anatarajia matokeo ya haraka, kama vile kufungua hati au kubonyeza kitufe kinachohitaji mahesabu. Hizi ni kipaumbele cha juu lakini chini ya mwingiliano wa mtumiaji.
3. **Matumizi:**
   - Kazi hizi ni za muda mrefu na kawaida huonyesha kiashiria cha maendeleo (k.m., kupakua faili, kuingiza data). Zina kipaumbele cha chini kuliko kazi zinazoanzishwa na mtumiaji na hazihitaji kumalizika mara moja.
4. **Mkondo wa Nyuma:**
   - Darasa hili ni kwa kazi zinazofanya kazi nyuma na hazionekani na mtumiaji. Hizi zinaweza kuwa kazi kama vile kutengeneza orodha, kusawazisha, au kuhifadhi nakala rudufu. Zina kipaumbele cha chini kabisa na athari ndogo kwa utendaji wa mfumo.

Kwa kutumia darasa za QoS, watengenezaji hawahitaji kusimamia nambari sahihi za vipaumbele bali badala yake wanazingatia asili ya kazi, na mfumo unaoanisha rasilimali za CPU ipasavyo.

Zaidi ya hayo, kuna **sera tofauti za upangaji wa mienendo** ambazo hufanya mifumo ya kuelekeza kikundi cha vigezo vya upangaji ambavyo upangaji utazingatia. Hii inaweza kufanywa kwa kutumia `thread_policy_[set/get]`. Hii inaweza kuwa na manufaa katika mashambulizi ya hali ya mbio.

## Mienendo ya MacOS

MacOS, kama mifumo mingine yoyote ya uendeshaji, hutoa njia na mbinu mbalimbali za **mienendo kuingiliana, kushirikiana, na kushiriki data**. Ingawa mbinu hizi ni muhimu kwa utendaji mzuri wa mfumo, zinaweza pia kutumiwa vibaya na wahalifu wa mtandao kufanya **shughuli za uovu**.

### Uingizaji wa Maktaba

Uingizaji wa Maktaba ni mbinu ambapo mshambuliaji **anashurutisha mchakato kupakia maktaba ya uovu**. Mara ilipoingizwa, maktaba inaendeshwa katika muktadha wa mchakato lengwa, ikimpa mshambuliaji ruhusa na ufikiaji sawa na mchakato.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Kufunga Kazi

Kufunga Kazi inahusisha **kukamata simu za kazi** au ujumbe ndani ya nambari ya programu. Kwa kufunga kazi, mshambuliaji anaweza **kurekebisha tabia** ya mchakato, kuchunguza data nyeti, au hata kupata udhibiti wa mwendelezo wa utekelezaji.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md](macos-function-hooking.md)
{% endcontent-ref %}

### Mawasiliano kati ya Mchakato

Mawasiliano kati ya Mchakato (IPC) inahusu njia tofauti ambazo michakato tofauti **hushiriki na kubadilishana data**. Ingawa IPC ni muhimu kwa maombi mengi halali, inaweza pia kutumiwa vibaya kukiuka kizuizi cha michakato, kuvuja taarifa nyeti, au kufanya hatua zisizoidhinishwa.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Uingizaji wa Programu za Electron

Programu za Electron zilizoendeshwa na mazingira maalum ya mazingira zinaweza kuwa hatarini kwa uingizaji wa mchakato:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Uingizaji wa Chromium

Inawezekana kutumia bendera `--load-extension` na `--use-fake-ui-for-media-stream` kufanya **shambulio la mtu katika kivinjari** kuruhusu kuiba kubonyeza, trafiki, vidakuzi, kuingiza skripti kwenye kurasa...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### NIB Chafu

Faili za NIB **hutambua vipengele vya interface ya mtumiaji (UI)** na mwingiliano wao ndani ya programu. Hata hivyo, wanaweza **kutekeleza amri za aina yoyote** na **Gatekeeper haisimamishi** programu iliyotekelezwa tayari kutoka kutekelezwa ikiwa **faili ya NIB imebadilishwa**. Kwa hivyo, zinaweza kutumika kufanya programu za aina yoyote kutekeleza amri za aina yoyote:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Uingizaji wa Programu za Java

Inawezekana kutumia uwezo fulani wa java (kama **`_JAVA_OPTS`** env variable) kufanya programu ya java kutekeleza **mimba ya nambari/amri**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Uingizaji wa Programu za .Net

Inawezekana kuingiza nambari kwenye programu za .Net kwa **kutumia vibaya kazi ya uchunguzi wa .Net** (ambayo haijalindwa na kinga za macOS kama uimarishaji wa wakati wa utekelezaji).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Uingizaji wa Perl

Angalia chaguzi tofauti za kufanya skripti ya Perl kutekeleza nambari ya aina yoyote katika:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Uingizaji wa Ruby

Pia inawezekana kutumia mazingira ya ruby kufanya skripti za aina yoyote kutekeleza nambari ya aina yoyote:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}
### Kuingiza Python

Ikiwa mazingira ya **`PYTHONINSPECT`** yanawekwa, mchakato wa python utaingia kwenye cli ya python mara tu itakapomaliza. Pia ni rahisi kutumia **`PYTHONSTARTUP`** kuonyesha skripti ya python itakayotekelezwa mwanzoni mwa kikao cha mwingiliano.\
Hata hivyo, kumbuka kwamba skripti ya **`PYTHONSTARTUP`** haitatekelezwa wakati **`PYTHONINSPECT`** inaunda kikao cha mwingiliano.

Mazingira mengine kama vile **`PYTHONPATH`** na **`PYTHONHOME`** pia yanaweza kuwa na manufaa kufanya amri ya python itekeleze nambari ya kupotosha.

Tambua kwamba programu zilizoundwa na **`pyinstaller`** hazitatumia mazingira haya hata kama zinatumika kwa kutumia python iliyowekwa.

{% hint style="danger" %}
Kwa ujumla, sikuweza kupata njia ya kufanya python itekeleze nambari ya kupotosha kwa kutumia mazingira ya mazingira.\
Hata hivyo, wengi wa watu hufunga pyhton kwa kutumia **Hombrew**, ambayo itaiweka pyhton katika **eneo linaloweza kuandikwa** kwa mtumiaji wa kawaida wa mfumo. Unaweza kuiteka na kitu kama:
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

* Kutumia **Mazingira ya Mazingira**: Itaangalia uwepo wa mojawapo ya mazingira ya mazingira yafuatayo: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** na **`ELECTRON_RUN_AS_NODE`**
* Kutumia simu za **`task_for_pid`**: Kugundua wakati mchakato mmoja anataka kupata **bandari ya kazi ya mwingine** ambayo inaruhusu kuingiza nambari katika mchakato.
* **Parameta za programu za Electron**: Mtu anaweza kutumia **`--inspect`**, **`--inspect-brk`** na **`--remote-debugging-port`** hoja ya mstari wa amri kuanza programu ya Electron katika hali ya kutatua matatizo, na hivyo kuingiza nambari ndani yake.
* Kutumia **viungo vya alama** au **viungo vya ngumu**: Kawaida unyanyasaji wa kawaida ni kuweka kiungo na **ruhusa zetu za mtumiaji**, na **kuielekeza kwenye eneo lenye ruhusa kubwa**. Uchunguzi ni rahisi sana kwa viungo vya ngumu na viungo vya alama. Ikiwa mchakato unaounda kiungo una **kiwango tofauti cha ruhusa** kuliko faili ya lengo, tunatuma **onyo**. Kwa bahati mbaya katika kesi ya viungo vya alama, kuzuia siozekani, kwani hatuna habari kuhusu marudio ya kiungo kabla ya uumbaji. Hii ni kizuizi cha mfumo wa EndpointSecuriy wa Apple.

### Simu zilizofanywa na michakato mingine

Katika [**chapisho hili la blogi**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kupata jinsi inavyowezekana kutumia kazi ya **`task_name_for_pid`** kupata habari kuhusu **michakato inayoingiza nambari katika mchakato** na kisha kupata habari kuhusu mchakato mwingine huo.

Tafadhali elewa kwamba ili kupiga simu kazi hiyo unahitaji kuwa **uid sawa** na yule anayekimbia mchakato au **root** (na inarudi habari kuhusu mchakato, sio njia ya kuingiza nambari).

## Marejeo

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
