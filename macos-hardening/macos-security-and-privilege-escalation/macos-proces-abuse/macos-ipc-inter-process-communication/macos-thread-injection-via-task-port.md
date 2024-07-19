# macOS Thread Injection via Task port

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

## Code

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Thread Hijacking

Kwanza, **`task_threads()`** inaitwa kwenye task port ili kupata orodha ya nyuzi kutoka kwa kazi ya mbali. Nyuzi moja inachaguliwa kwa ajili ya hijacking. Njia hii inatofautiana na mbinu za kawaida za kuingiza msimbo kwani kuunda nyuzi mpya za mbali kunakatazwa kutokana na ulinzi mpya unaozuia `thread_create_running()`.

Ili kudhibiti nyuzi, **`thread_suspend()`** inaitwa, ikisimamisha utekelezaji wake.

Operesheni pekee zinazoruhusiwa kwenye nyuzi ya mbali zinahusisha **kusimamisha** na **kuanzisha** hiyo, **kupata** na **kubadilisha** thamani zake za register. Kuitwa kwa kazi za mbali kunaanzishwa kwa kuweka register `x0` hadi `x7` kwa **hoja**, kuunda **`pc`** ili kuelekeza kwenye kazi inayotakiwa, na kuanzisha nyuzi. Kuhakikisha kuwa nyuzi haiporomoki baada ya kurudi kunahitaji kugundua kurudi.

Stratejia moja inahusisha **kujiandikisha kwa mhandisi wa makosa** kwa nyuzi ya mbali kwa kutumia `thread_set_exception_ports()`, kuweka register `lr` kwenye anwani isiyo sahihi kabla ya wito wa kazi. Hii inasababisha makosa baada ya utekelezaji wa kazi, ikituma ujumbe kwenye bandari ya makosa, ikiruhusu ukaguzi wa hali ya nyuzi ili kurejesha thamani ya kurudi. Vinginevyo, kama ilivyopitishwa kutoka kwa exploit ya triple_fetch ya Ian Beer, `lr` inawekwa ili kuzunguka bila kikomo. Registers za nyuzi kisha zinaangaliwa kwa karibu hadi **`pc` inapoelekeza kwenye hiyo amri**.

## 2. Mach ports for communication

Awamu inayofuata inahusisha kuanzisha Mach ports ili kuwezesha mawasiliano na nyuzi ya mbali. Bandari hizi ni muhimu katika kuhamasisha haki za kutuma na kupokea zisizo na mipaka kati ya kazi.

Kwa mawasiliano ya pande mbili, haki mbili za kupokea Mach zinaundwa: moja katika kazi ya ndani na nyingine katika kazi ya mbali. Kisha, haki ya kutuma kwa kila bandari inahamishwa kwa kazi ya mwenzake, ikiruhusu kubadilishana ujumbe.

Kuzingatia bandari ya ndani, haki ya kupokea inashikiliwa na kazi ya ndani. Bandari inaundwa kwa `mach_port_allocate()`. Changamoto iko katika kuhamasisha haki ya kutuma kwa bandari hii kwenye kazi ya mbali.

Stratejia inahusisha kutumia `thread_set_special_port()` kuweka haki ya kutuma kwa bandari ya ndani katika `THREAD_KERNEL_PORT` ya nyuzi ya mbali. Kisha, nyuzi ya mbali inaelekezwa kuita `mach_thread_self()` ili kupata haki ya kutuma.

Kwa bandari ya mbali, mchakato kimsingi unarudiwa. Nyuzi ya mbali inaelekezwa kuunda bandari ya Mach kupitia `mach_reply_port()` (kama `mach_port_allocate()` haiwezi kutumika kutokana na mfumo wake wa kurudi). Baada ya kuundwa kwa bandari, `mach_port_insert_right()` inaitwa katika nyuzi ya mbali ili kuanzisha haki ya kutuma. Haki hii kisha inahifadhiwa kwenye kernel kwa kutumia `thread_set_special_port()`. Kurudi kwenye kazi ya ndani, `thread_get_special_port()` inatumika kwenye nyuzi ya mbali ili kupata haki ya kutuma kwa bandari mpya ya Mach iliyotolewa katika kazi ya mbali.

Kukamilika kwa hatua hizi kunasababisha kuanzishwa kwa Mach ports, kuweka msingi wa mawasiliano ya pande mbili.

## 3. Basic Memory Read/Write Primitives

Katika sehemu hii, lengo ni kutumia primitive ya kutekeleza ili kuanzisha primitive za msingi za kusoma na kuandika kumbukumbu. Hatua hizi za awali ni muhimu kwa kupata udhibiti zaidi juu ya mchakato wa mbali, ingawa primitive katika hatua hii hazitakuwa na matumizi mengi. Hivi karibuni, zitaimarishwa kuwa toleo za juu zaidi.

### Memory Reading and Writing Using Execute Primitive

Lengo ni kufanya kusoma na kuandika kumbukumbu kwa kutumia kazi maalum. Kwa kusoma kumbukumbu, kazi zinazofanana na muundo ufuatao zinatumika:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Na kwa kuandika kwenye kumbukumbu, kazi zinazofanana na muundo huu hutumiwa:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Hizi kazi zinahusiana na maagizo ya mkusanyiko yaliyotolewa:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Kutambua Kazi Zinazofaa

Kuchunguza maktaba za kawaida kumefichua wagombea wanaofaa kwa ajili ya operesheni hizi:

1. **Kusoma Kumbukumbu:**
Funguo la `property_getName()` kutoka kwenye [maktaba ya wakati wa Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) linatambuliwa kama kazi inayofaa kwa kusoma kumbukumbu. Kazi hiyo imeelezwa hapa chini:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Hii kazi inafanya kazi kama `read_func` kwa kurudisha uwanja wa kwanza wa `objc_property_t`.

2. **Kuandika Kumbukumbu:**
Kupata kazi iliyojengwa awali ya kuandika kumbukumbu ni changamoto zaidi. Hata hivyo, kazi ya `_xpc_int64_set_value()` kutoka libxpc ni mgombea mzuri ikiwa na disassembly ifuatayo:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Ili kufanya kuandika 64-bit katika anwani maalum, wito wa mbali umeundwa kama:
```c
_xpc_int64_set_value(address - 0x18, value)
```
With these primitives established, the stage is set for creating shared memory, marking a significant progression in controlling the remote process.

## 4. Usanidi wa Kumbukumbu ya Pamoja

Lengo ni kuanzisha kumbukumbu ya pamoja kati ya kazi za ndani na za mbali, kuifanya iwe rahisi kuhamasisha data na kuwezesha wito wa kazi zenye hoja nyingi. Njia hii inahusisha kutumia `libxpc` na aina ya kitu chake `OS_xpc_shmem`, ambayo imejengwa juu ya entries za kumbukumbu za Mach.

### Muonekano wa Mchakato:

1. **Ugawaji wa Kumbukumbu**:
- Panga kumbukumbu kwa ajili ya kushiriki kwa kutumia `mach_vm_allocate()`.
- Tumia `xpc_shmem_create()` kuunda kitu cha `OS_xpc_shmem` kwa ajili ya eneo la kumbukumbu lililotengwa. Kazi hii itasimamia uundaji wa entry ya kumbukumbu ya Mach na kuhifadhi haki ya kutuma ya Mach kwenye offset `0x18` ya kitu cha `OS_xpc_shmem`.

2. **Kuunda Kumbukumbu ya Pamoja katika Mchakato wa Mbali**:
- Panga kumbukumbu kwa ajili ya kitu cha `OS_xpc_shmem` katika mchakato wa mbali kwa wito wa mbali kwa `malloc()`.
- Nakili maudhui ya kitu cha ndani cha `OS_xpc_shmem` kwenye mchakato wa mbali. Hata hivyo, nakala hii ya awali itakuwa na majina yasiyo sahihi ya entry za kumbukumbu za Mach kwenye offset `0x18`.

3. **Kurekebisha Entry ya Kumbukumbu ya Mach**:
- Tumia njia ya `thread_set_special_port()` kuingiza haki ya kutuma kwa entry ya kumbukumbu ya Mach kwenye kazi ya mbali.
- Rekebisha uwanja wa entry ya kumbukumbu ya Mach kwenye offset `0x18` kwa kuandika upya kwa jina la entry ya kumbukumbu ya mbali.

4. **Kumaliza Usanidi wa Kumbukumbu ya Pamoja**:
- Thibitisha kitu cha mbali cha `OS_xpc_shmem`.
- Kuanzisha ramani ya kumbukumbu ya pamoja kwa wito wa mbali kwa `xpc_shmem_remote()`.

Kwa kufuata hatua hizi, kumbukumbu ya pamoja kati ya kazi za ndani na za mbali itakuwa imewekwa kwa ufanisi, ikiruhusu uhamasishaji wa data rahisi na utekelezaji wa kazi zinazohitaji hoja nyingi.

## Mifano ya Kode za Ziada

Kwa ugawaji wa kumbukumbu na uundaji wa kitu cha kumbukumbu ya pamoja:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Ili kuunda na kurekebisha kitu cha kumbukumbu kilichoshirikiwa katika mchakato wa mbali:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Kumbuka kushughulikia maelezo ya Mach ports na majina ya kuingia kwenye kumbukumbu kwa usahihi ili kuhakikisha kuwa usanidi wa kumbukumbu iliyoshirikiwa unafanya kazi ipasavyo.

## 5. Kufikia Udhibiti Kamili

Baada ya kufanikiwa kuanzisha kumbukumbu iliyoshirikiwa na kupata uwezo wa kutekeleza kwa njia isiyo na mipaka, kimsingi tumepata udhibiti kamili juu ya mchakato wa lengo. Kazi muhimu zinazowezesha udhibiti huu ni:

1. **Operesheni za Kumbukumbu zisizo na mipaka**:
- Fanya usomaji wa kumbukumbu zisizo na mipaka kwa kuita `memcpy()` ili nakala data kutoka kwenye eneo lililosharikiwa.
- Tekeleza uandishi wa kumbukumbu zisizo na mipaka kwa kutumia `memcpy()` kuhamasisha data kwenye eneo lililosharikiwa.

2. **Kushughulikia Kuitwa kwa Kazi zenye Hoja Nyingi**:
- Kwa kazi zinazohitaji zaidi ya hoja 8, panga hoja za ziada kwenye stack kwa kufuata kanuni ya kuita.

3. **Uhamisho wa Mach Port**:
- Hamisha Mach ports kati ya kazi kupitia ujumbe wa Mach kupitia bandari zilizowekwa awali.

4. **Uhamisho wa File Descriptor**:
- Hamisha file descriptors kati ya michakato kwa kutumia fileports, mbinu iliyosisitizwa na Ian Beer katika `triple_fetch`.

Udhibiti huu wa kina umejumuishwa ndani ya maktaba ya [threadexec](https://github.com/bazad/threadexec), ikitoa utekelezaji wa kina na API rafiki kwa mtumiaji kwa mwingiliano na mchakato wa mwathirika.

## Maelezo Muhimu:

- Hakikisha matumizi sahihi ya `memcpy()` kwa operesheni za kusoma/kandika kumbukumbu ili kudumisha utulivu wa mfumo na uadilifu wa data.
- Unapohamisha Mach ports au file descriptors, fuata itifaki sahihi na shughuikia rasilimali kwa uwajibikaji ili kuzuia leaks au ufikiaji usio na mpango.

Kwa kufuata miongozo hii na kutumia maktaba ya `threadexec`, mtu anaweza kudhibiti kwa ufanisi na kuingiliana na michakato kwa kiwango kidogo, akipata udhibiti kamili juu ya mchakato wa lengo.

## Marejeo
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

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
