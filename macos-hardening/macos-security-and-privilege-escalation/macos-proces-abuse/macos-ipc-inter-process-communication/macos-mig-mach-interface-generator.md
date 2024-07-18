# macOS MIG - Mach Interface Generator

{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}

## Podstawowe informacje

MIG został stworzony, aby **uproszczać proces tworzenia kodu Mach IPC**. W zasadzie **generuje wymagany kod** do komunikacji serwera i klienta z daną definicją. Nawet jeśli wygenerowany kod jest brzydki, programista będzie musiał go tylko zaimportować, a jego kod będzie znacznie prostszy niż wcześniej.

Definicja jest określana w Interface Definition Language (IDL) przy użyciu rozszerzenia `.defs`.

Te definicje mają 5 sekcji:

* **Deklaracja podsystemu**: Słowo kluczowe podsystem jest używane do wskazania **nazwy** i **id**. Można również oznaczyć go jako **`KernelServer`**, jeśli serwer ma działać w jądrze.
* **Dołączenia i importy**: MIG używa preprocesora C, więc może korzystać z importów. Ponadto możliwe jest użycie `uimport` i `simport` dla kodu generowanego przez użytkownika lub serwer.
* **Deklaracje typów**: Można zdefiniować typy danych, chociaż zazwyczaj importuje się `mach_types.defs` i `std_types.defs`. Dla niestandardowych można użyć pewnej składni:
* \[i`n/out]tran`: Funkcja, która musi zostać przetłumaczona z przychodzącej lub do wychodzącej wiadomości
* `c[user/server]type`: Mapowanie na inny typ C.
* `destructor`: Wywołaj tę funkcję, gdy typ zostanie zwolniony.
* **Operacje**: To są definicje metod RPC. Istnieje 5 różnych typów:
* `routine`: Oczekuje odpowiedzi
* `simpleroutine`: Nie oczekuje odpowiedzi
* `procedure`: Oczekuje odpowiedzi
* `simpleprocedure`: Nie oczekuje odpowiedzi
* `function`: Oczekuje odpowiedzi

### Przykład

Utwórz plik definicji, w tym przypadku z bardzo prostą funkcją:

{% code title="myipc.defs" %}
```cpp
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
server_port :  mach_port_t;
n1          :  uint32_t;
n2          :  uint32_t);
```
{% endcode %}

Należy pamiętać, że pierwszym **argumentem jest port do powiązania**, a MIG będzie **automatycznie obsługiwać port odpowiedzi** (chyba że w kodzie klienta zostanie wywołane `mig_get_reply_port()`). Ponadto **ID operacji** będzie **sekwencyjne**, zaczynając od wskazanego ID podsystemu (więc jeśli operacja jest przestarzała, zostaje usunięta, a `skip` jest używane, aby nadal używać jej ID).

Teraz użyj MIG do wygenerowania kodu serwera i klienta, które będą mogły komunikować się ze sobą, aby wywołać funkcję Odejmowania:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
W bieżącym katalogu zostanie utworzonych kilka nowych plików.

{% hint style="success" %}
Możesz znaleźć bardziej złożony przykład w swoim systemie za pomocą: `mdfind mach_port.defs`\
A następnie możesz go skompilować z tego samego folderu co plik za pomocą: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`
{% endhint %}

W plikach **`myipcServer.c`** i **`myipcServer.h`** znajdziesz deklarację i definicję struktury **`SERVERPREFmyipc_subsystem`**, która w zasadzie definiuje funkcję do wywołania na podstawie otrzymanego identyfikatora wiadomości (wskazaliśmy początkowy numer 500):

{% tabs %}
{% tab title="myipcServer.c" %}
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
myipc_server_routine,
500, // start ID
501, // end ID
(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
(vm_address_t)0,
{
{ (mig_impl_routine_t) 0,
// Function to call
(mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
}
};
```
{% endtab %}

{% tab title="myipcServer.h" %}Tytuł: myipcServer.h{% endtab %}
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
mig_server_routine_t	server;	/* Server routine */
mach_msg_id_t	start;	/* Min routine number */
mach_msg_id_t	end;	/* Max routine number + 1 */
unsigned int	maxsize;	/* Max msg size */
vm_address_t	reserved;	/* Reserved */
struct routine_descriptor	/* Array of routine descriptors */
routine[1];
} SERVERPREFmyipc_subsystem;
```
{% endtab %}
{% endtabs %}

Na podstawie poprzedniej struktury funkcja **`myipc_server_routine`** otrzyma **ID wiadomości** i zwróci odpowiednią funkcję do wywołania:
```c
mig_external mig_routine_t myipc_server_routine
(mach_msg_header_t *InHeadP)
{
int msgh_id;

msgh_id = InHeadP->msgh_id - 500;

if ((msgh_id > 0) || (msgh_id < 0))
return 0;

return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```
W tym przykładzie zdefiniowaliśmy tylko 1 funkcję w definicjach, ale gdybyśmy zdefiniowali więcej funkcji, znajdowałyby się one wewnątrz tablicy **`SERVERPREFmyipc_subsystem`**, a pierwsza zostałaby przypisana do ID **500**, druga do ID **501**...

Jeśli oczekiwano, że funkcja ma wysłać **odpowiedź**, funkcja `mig_internal kern_return_t __MIG_check__Reply__<name>` również istniałaby.

Tak naprawdę można zidentyfikować tę relację w strukturze **`subsystem_to_name_map_myipc`** z pliku **`myipcServer.h`** (**`subsystem_to_name_map_***`** w innych plikach):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Ostatecznie, kolejną ważną funkcją, która sprawi, że serwer będzie działać, będzie **`myipc_server`**, która faktycznie **wywoła funkcję** związaną z otrzymanym identyfikatorem:

<pre class="language-c"><code class="lang-c">mig_external boolean_t myipc_server
(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
/*
* typedef struct {
* 	mach_msg_header_t Head;
* 	NDR_record_t NDR;
* 	kern_return_t RetCode;
* } mig_reply_error_t;
*/

mig_routine_t routine;

OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
/* Minimal size: routine() will update it if different */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id &#x3C; 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

Sprawdź wcześniej wyróżnione linie, które uzyskują dostęp do funkcji do wywołania na podstawie identyfikatora.

Poniżej znajduje się kod tworzący prosty **serwer** i **klient**, gdzie klient może wywoływać funkcje odejmowania na serwerze:

{% tabs %}
{% tab title="myipc_server.c" %}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
return KERN_SUCCESS;
}

int main() {

mach_port_t port;
kern_return_t kr;

// Register the mach service
kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_check_in() failed with code 0x%x\n", kr);
return 1;
}

// myipc_server is the function that handles incoming messages (check previous exlpanation)
mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{% endtab %}

{% tab title="myipc_client.c" %}{% endtab %}
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("Port right name %d\n", port);
USERPREFSubtract(port, 40, 2);
}
```
{% endtab %}
{% endtabs %}

### Rekord NDR

Rekord NDR jest eksportowany przez `libsystem_kernel.dylib` i jest to struktura, która pozwala MIG na **przekształcanie danych w sposób niezależny od systemu**, na którym jest używany, ponieważ MIG miał być używany między różnymi systemami (a nie tylko na tym samym urządzeniu).

Jest to interesujące, ponieważ jeśli `_NDR_record` zostanie znaleziony w binarnym jako zależność (`jtool2 -S <binary> | grep NDR` lub `nm`), oznacza to, że binarny jest klientem lub serwerem MIG.

Co więcej, **serwery MIG** mają tabelę dyspozytorników w `__DATA.__const` (lub w `__CONST.__constdata` w jądrze macOS i `__DATA_CONST.__const` w innych jądrach \*OS). Można to wyeksportować za pomocą **`jtool2`**.

Natomiast **klienci MIG** będą używać `__NDR_record` do wysyłania z `__mach_msg` do serwerów.

## Analiza Binarna

### jtool

Ponieważ wiele binarnych plików teraz używa MIG do eksponowania portów mach, interesujące jest wiedzieć, jak **zidentyfikować użycie MIG** oraz **funkcje, które MIG wykonuje** przy każdym identyfikatorze wiadomości.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) potrafi analizować informacje MIG z pliku Mach-O, wskazując identyfikator wiadomości i identyfikując funkcję do wykonania:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Ponadto funkcje MIG są tylko opakowaniami rzeczywistej funkcji, która jest wywoływana, co oznacza, że uzyskując jej rozkład i przeszukując go pod kątem BL, możesz być w stanie znaleźć rzeczywistą funkcję, która jest wywoływana:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Montaż

Wcześniej wspomniano, że funkcją, która będzie **odpowiadać za wywołanie odpowiedniej funkcji w zależności od otrzymanego identyfikatora wiadomości**, będzie `myipc_server`. Jednak zazwyczaj nie będziesz mieć symboli binarnych (brak nazw funkcji), więc interesujące jest **sprawdzenie, jak wygląda zdekompilowany kod**, ponieważ zawsze będzie bardzo podobny (kod tej funkcji jest niezależny od funkcji wystawionych):

{% tabs %}
{% tab title="myipc_server zdekompilowany 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Instrukcje początkowe do znalezienia odpowiednich wskaźników funkcji
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Wywołanie sign_extend_64, które pomaga zidentyfikować tę funkcję
// To zapisuje w rax wskaźnik do wywołania, które trzeba wywołać
// Sprawdź użycie adresu 0x100004040 (tablica adresów funkcji)
// 0x1f4 = 500 (początkowe ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Warunek if - else, jeśli if zwraca false, a else wywołuje odpowiednią funkcję i zwraca true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Obliczony adres wywołujący odpowiednią funkcję z 2 argumentami
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
rax = var_4;
return rax;
}
</code></pre>
{% endtab %}

{% tab title="myipc_server zdekompilowany 2" %}
To ta sama funkcja zdekompilowana w innej wersji Hoppera:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Instrukcje początkowe do znalezienia odpowiednich wskaźników funkcji
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS &#x26; G) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 &#x3C; 0x0) {
if (CPU_FLAGS &#x26; L) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (początkowe ID)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS &#x26; NE) {
r8 = 0x1;
}
}
// To samo if else co w poprzedniej wersji
// Sprawdź użycie adresu 0x100004040 (tablica adresów funkcji)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Wywołanie obliczonego adresu, gdzie powinna znajdować się funkcja
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>
{% endtab %}
{% endtabs %}

Faktycznie, jeśli przejdziesz do funkcji **`0x100004000`**, znajdziesz tablicę struktur **`routine_descriptor`**. Pierwszy element struktury to **adres**, gdzie jest zaimplementowana **funkcja**, a **struktura zajmuje 0x28 bajtów**, więc co 0x28 bajtów (zaczynając od bajtu 0) można uzyskać 8 bajtów, które będą **adresem funkcji**, która zostanie wywołana:

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Te dane można wyodrębnić [**korzystając z tego skryptu Hoppera**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).
### Debug

Kod generowany przez MIG również wywołuje `kernel_debug`, aby generować logi dotyczące operacji przy wejściu i wyjściu. Można je sprawdzić za pomocą **`trace`** lub **`kdv`**: `kdv all | grep MIG`

## References

* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{% hint style="success" %}
Naucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
