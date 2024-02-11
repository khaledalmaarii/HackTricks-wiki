# Uingizaji wa Thread kwenye macOS kupitia Task port

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kanuni

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Udukuzi wa Thread

Kwanza, kazi ya **`task_threads()`** inaitwa kwenye task port ili kupata orodha ya nyuzi kutoka kwa kazi ya mbali. Nyuzi moja inachaguliwa kwa udukuzi. Njia hii inatofautiana na njia za kawaida za kuingiza nambari kama kuunda nyuzi mpya ya mbali imezuiwa kutokana na kinga mpya inayozuia `thread_create_running()`.

Kudhibiti nyuzi, **`thread_suspend()`** inaitwa, ikisimamisha utekelezaji wake.

Operesheni pekee zinazoruhusiwa kwenye nyuzi ya mbali ni **kusimamisha** na **kuanza** nyuzi hiyo, **kupata** na **kubadilisha** thamani za usajili wake. Wito wa kazi za mbali huanzishwa kwa kuweka usajili `x0` hadi `x7` kama **hoja**, kusanidi **`pc`** kuelekea kazi inayotakiwa, na kuamsha nyuzi. Kuhakikisha nyuzi haipati ajali baada ya kurudi kunahitaji kugundua kurudi.

Mbinu moja inahusisha **kujiandikisha kwa mchakato wa kipekee** kwa nyuzi ya mbali kwa kutumia `thread_set_exception_ports()`, kuweka usajili wa `lr` kwa anwani batili kabla ya wito wa kazi. Hii inasababisha kuzuka kwa kipekee baada ya utekelezaji wa kazi, kutuma ujumbe kwenye bandari ya kipekee, kuruhusu ukaguzi wa hali ya nyuzi kupona thamani ya kurudi. Kwa njia nyingine, kama ilivyochukuliwa kutoka kwa udanganyifu wa triple\_fetch wa Ian Beer, `lr` inawekwa kwenye mzunguko usio na mwisho. Usajili wa nyuzi basi unafuatiliwa mara kwa mara hadi **`pc` inapoelekeza kwenye maagizo hayo**.

## 2. Mach ports kwa mawasiliano

Hatua inayofuata inahusisha kuanzisha Mach ports ili kurahisisha mawasiliano na nyuzi ya mbali. Bandari hizi ni muhimu katika kuhamisha haki za kutuma na kupokea za kiholela kati ya kazi.

Kwa mawasiliano ya pande mbili, haki mbili za kupokea za Mach zinaundwa: moja katika kazi ya ndani na nyingine katika kazi ya mbali. Baadaye, haki ya kutuma kwa kila bandari inahamishiwa kwa kazi mwenza, kuruhusu kubadilishana ujumbe.

Kuzingatia bandari ya ndani, haki ya kupokea inashikiliwa na kazi ya ndani. Bandari inaundwa na `mach_port_allocate()`. Changamoto inapatikana katika kuhamisha haki ya kutuma kwa bandari hii kwenda kwa kazi ya mbali.

Mbinu inahusisha kutumia `thread_set_special_port()` kuweka haki ya kutuma kwa bandari ya ndani kwenye `THREAD_KERNEL_PORT` ya nyuzi ya mbali. Kisha, nyuzi ya mbali inaagizwa kuita `mach_thread_self()` ili kupata haki ya kutuma.

Kwa bandari ya mbali, mchakato ni kinyume kabisa. Nyuzi ya mbali inaelekezwa kuzalisha bandari ya Mach kupitia `mach_reply_port()` (kwa kuwa `mach_port_allocate()` haifai kutokana na utaratibu wake wa kurudi). Baada ya kuundwa kwa bandari, `mach_port_insert_right()` inaitwa kwenye nyuzi ya mbali kuweka haki ya kutuma. Haki hii kisha inawekwa kwenye kernel kwa kutumia `thread_set_special_port()`. Kurudi kwenye kazi ya ndani, `thread_get_special_port()` inatumika kwenye nyuzi ya mbali kupata haki ya kutuma kwa bandari ya Mach iliyotengwa hivi karibuni kwenye kazi ya mbali.

Kukamilika kwa hatua hizi kunasababisha kuanzishwa kwa Mach ports, kuweka msingi wa mawasiliano ya pande mbili.

## 3. Misingi ya Kusoma/Kuandika Kumbukumbu

Katika sehemu hii, lengo ni kutumia mbinu ya kutekeleza kusoma na kuandika kumbukumbu za msingi. Hatua hizi za awali ni muhimu kwa kupata udhibiti zaidi juu ya mchakato wa mbali, ingawa misingi katika hatua hii haitumiki kwa madhumuni mengi. Hivi karibuni, zitaboreshwa kuwa toleo la juu zaidi.

### Kusoma na Kuandika Kumbukumbu Kwa Kutumia Mbinu ya Kutekeleza

Lengo ni kusoma na kuandika kumbukumbu kwa kutumia kazi maalum. Kwa kusoma kumbukumbu, hutumiwa kazi zinazofanana na muundo ufuatao:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Na kwa kuandika kwenye kumbukumbu, hutumiwa kazi zinazofanana na muundo huu:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Hizi kazi zinafanana na maagizo ya mkutano yaliyotolewa:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Kutambua Kazi Zinazofaa

Uchunguzi wa maktaba za kawaida ulifunua wagombea sahihi kwa shughuli hizi:

1. **Kusoma Kumbukumbu:**
Kazi ya `property_getName()` kutoka [Maktaba ya Objective-C runtime](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) imebainishwa kuwa kazi inayofaa kwa kusoma kumbukumbu. Kazi hiyo imefafanuliwa hapa chini:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Hii kazi inafanya kazi kama `read_func` kwa kurudisha uga wa kwanza wa `objc_property_t`.

2. **Kuandika Kumbukumbu:**
Kupata kazi iliyotengenezwa tayari ya kuandika kumbukumbu ni changamoto zaidi. Walakini, kazi ya `_xpc_int64_set_value()` kutoka kwa libxpc ni mgombea mzuri na disassembly ifuatayo:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Kufanya uandishi wa biti 64 kwenye anwani maalum, wito wa mbali unajengwa kama ifuatavyo:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Kwa kutumia msingi huu, hatua zimeandaliwa kwa ajili ya kuunda kumbukumbu ya pamoja, ambayo ni hatua muhimu katika kudhibiti mchakato wa mbali.

## 4. Kuweka Kumbukumbu ya Pamoja

Lengo ni kuweka kumbukumbu ya pamoja kati ya kazi za ndani na za mbali, kurahisisha uhamishaji wa data na kurahisisha wito wa kazi zenye hoja nyingi. Njia inahusisha kutumia `libxpc` na aina yake ya kitu cha `OS_xpc_shmem`, ambayo imejengwa kwenye kuingia kumbukumbu ya Mach.

### Muhtasari wa Mchakato:

1. **Ugawaji wa Kumbukumbu**:
- Gawa kumbukumbu kwa ajili ya kushiriki kwa kutumia `mach_vm_allocate()`.
- Tumia `xpc_shmem_create()` kuunda kitu cha `OS_xpc_shmem` kwa eneo la kumbukumbu iliyotengwa. Kazi hii itasimamia uundaji wa kuingia kumbukumbu ya Mach na kuhifadhi haki ya kutuma ya Mach kwenye nafasi ya `0x18` ya kitu cha `OS_xpc_shmem`.

2. **Kuunda Kumbukumbu ya Pamoja katika Mchakato wa Mbali**:
- Gawa kumbukumbu kwa ajili ya kitu cha `OS_xpc_shmem` katika mchakato wa mbali kwa kutumia wito wa mbali kwa `malloc()`.
- Nakili maudhui ya kitu cha `OS_xpc_shmem` cha ndani kwenda kwenye mchakato wa mbali. Hata hivyo, nakala hii ya awali itakuwa na majina ya kuingia kumbukumbu ya Mach yasiyofaa kwenye nafasi ya `0x18`.

3. **Kurekebisha Kuingia Kumbukumbu ya Mach**:
- Tumia njia ya `thread_set_special_port()` kuweka haki ya kutuma ya kuingia kumbukumbu ya Mach kwenye kazi ya mbali.
- Rekebisha uga wa kuingia kumbukumbu ya Mach kwenye nafasi ya `0x18` kwa kuandika juu yake jina la kuingia kumbukumbu ya mbali.

4. **Kukamilisha Kuweka Kumbukumbu ya Pamoja**:
- Thibitisha kitu cha `OS_xpc_shmem` cha mbali.
- Weka ramani ya kumbukumbu ya pamoja kwa kutumia wito wa mbali kwa `xpc_shmem_remote()`.

Kwa kufuata hatua hizi, kumbukumbu ya pamoja kati ya kazi za ndani na za mbali itawekwa kwa ufanisi, kuruhusu uhamishaji wa data kwa urahisi na utekelezaji wa kazi zinazohitaji hoja nyingi.

## Vifungu vingine vya Kanuni

Kwa ugawaji wa kumbukumbu na uundaji wa kitu cha kumbukumbu ya pamoja:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Kwa kujenga na kusahihisha kifaa cha kumbukumbu kinachoshiriki katika mchakato wa mbali:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Kumbuka kushughulikia maelezo ya Mach ports na majina ya kumbukumbu kwa usahihi ili kuhakikisha kuwa usanidi wa kumbukumbu ulioshiriki unafanya kazi vizuri.


## 5. Kufikia Udhibiti Kamili

Baada ya kuanzisha kumbukumbu iliyoshiriki na kupata uwezo wa kutekeleza kwa hiari, kimsingi tumepata udhibiti kamili juu ya mchakato wa lengo. Kazi muhimu zinazoruhusu udhibiti huu ni:

1. **Operesheni za Kumbukumbu za Hiari**:
- Fanya kusoma kumbukumbu za hiari kwa kuita `memcpy()` ili kunakili data kutoka eneo lililoshirikiwa.
- Tekeleza kuandika kumbukumbu za hiari kwa kutumia `memcpy()` kuhamisha data kwenye eneo lililoshirikiwa.

2. **Kushughulikia Wito wa Kazi na Vigezo Vingi**:
- Kwa kazi zinazohitaji zaidi ya vigezo 8, panga vigezo ziada kwenye steki kulingana na mkataba wa wito.

3. **Uhamisho wa Mach Port**:
- Hamisha Mach ports kati ya kazi kupitia ujumbe wa Mach kupitia bandari zilizowekwa hapo awali.

4. **Uhamisho wa Descripta ya Faili**:
- Hamisha descripta za faili kati ya michakato kwa kutumia fileports, mbinu iliyobainishwa na Ian Beer katika `triple_fetch`.

Udhibiti kamili huu umefungwa ndani ya maktaba ya [threadexec](https://github.com/bazad/threadexec), ikitoa utekelezaji wa kina na kiolesura cha mtumiaji rafiki kwa mwingiliano na mchakato wa mwathirika.

## Mambo Muhimu ya Kuzingatia:

- Hakikisha matumizi sahihi ya `memcpy()` kwa operesheni za kusoma/kuandika kumbukumbu ili kudumisha utulivu wa mfumo na usahihi wa data.
- Wakati wa kuhamisha Mach ports au descripta za faili, fuata itifaki sahihi na shughulikia rasilimali kwa uwajibikaji ili kuzuia uvujaji au ufikiaji usiokusudiwa.

Kwa kufuata mwongozo huu na kutumia maktaba ya `threadexec`, mtu anaweza kusimamia na kuingiliana na michakato kwa kiwango cha kina, kufikia udhibiti kamili juu ya mchakato wa lengo.

## Marejeo
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
