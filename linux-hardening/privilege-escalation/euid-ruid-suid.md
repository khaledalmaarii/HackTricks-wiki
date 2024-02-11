# euid, ruid, suid

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

### Zmienne identyfikujące użytkownika

- **`ruid`**: **Rzeczywisty identyfikator użytkownika** oznacza użytkownika, który uruchomił proces.
- **`euid`**: Znany jako **efektywny identyfikator użytkownika**, reprezentuje tożsamość użytkownika wykorzystywaną przez system do określenia uprawnień procesu. Ogólnie rzecz biorąc, `euid` odzwierciedla `ruid`, z wyjątkiem przypadków, gdy wykonuje się binarny plik SetUID, w którym `euid` przyjmuje tożsamość właściciela pliku, co umożliwia przyznanie określonych uprawnień operacyjnych.
- **`suid`**: Ten **zapisany identyfikator użytkownika** jest kluczowy, gdy proces o wysokich uprawnieniach (zwykle uruchamiany jako root) musi tymczasowo zrzec się swoich uprawnień, aby wykonać określone zadania, a następnie odzyskać swoje początkowe podwyższone uprawnienia.

#### Ważna uwaga
Proces nieoperujący jako root może jedynie modyfikować swoje `euid`, aby dopasować go do bieżącego `ruid`, `euid` lub `suid`.

### Zrozumienie funkcji set*uid

- **`setuid`**: Wbrew początkowym założeniom, `setuid` głównie modyfikuje `euid`, a nie `ruid`. W przypadku procesów o uprzywilejowanych uprawnieniach, dopasowuje `ruid`, `euid` i `suid` do określonego użytkownika, często roota, co skutkuje ustaleniem tych identyfikatorów dzięki nadpisywaniu `suid`. Szczegółowe informacje można znaleźć w [manuale setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** i **`setresuid`**: Te funkcje umożliwiają subtelne dostosowanie `ruid`, `euid` i `suid`. Jednak ich możliwości zależą od poziomu uprzywilejowania procesu. Dla procesów nie będących rootem, modyfikacje są ograniczone do bieżących wartości `ruid`, `euid` i `suid`. W przypadku procesów roota lub posiadających zdolność `CAP_SETUID` można przypisać dowolne wartości do tych identyfikatorów. Więcej informacji można znaleźć w [manuale setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) i [manuale setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Te funkcjonalności zostały zaprojektowane nie jako mechanizm zabezpieczeń, ale jako ułatwienie zamierzonego przepływu operacyjnego, na przykład gdy program przyjmuje tożsamość innego użytkownika poprzez zmianę swojego efektywnego identyfikatora użytkownika.

Warto zauważyć, że chociaż `setuid` może być powszechnie stosowany do podwyższania uprawnień do roota (ponieważ dopasowuje wszystkie identyfikatory do roota), różnicowanie między tymi funkcjami jest kluczowe dla zrozumienia i manipulowania zachowaniem identyfikatorów użytkownika w różnych scenariuszach.

### Mechanizmy wykonania programów w systemie Linux

#### Wywołanie systemowe **`execve`**
- **Funkcjonalność**: `execve` uruchamia program określony przez pierwszy argument. Przyjmuje dwa argumenty tablicowe, `argv` dla argumentów i `envp` dla środowiska.
- **Zachowanie**: Zachowuje przestrzeń pamięci wywołującego, ale odświeża stos, stertę i segmenty danych. Kod programu zostaje zastąpiony przez nowy program.
- **Zachowanie identyfikatorów użytkownika**:
- `ruid`, `euid` i dodatkowe identyfikatory grupy pozostają niezmienione.
- `euid` może ulec subtelnej zmianie, jeśli nowy program ma ustawiony bit SetUID.
- `suid` zostaje zaktualizowany z `euid` po wykonaniu.
- **Dokumentacja**: Szczegółowe informacje można znaleźć w [manuale `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### Funkcja **`system`**
- **Funkcjonalność**: W przeciwieństwie do `execve`, `system` tworzy proces potomny za pomocą `fork` i wykonuje polecenie w tym procesie potomnym za pomocą `execl`.
- **Wykonanie polecenia**: Wykonuje polecenie za pomocą `sh` i `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Zachowanie**: Ponieważ `execl` jest formą `execve`, działa podobnie, ale w kontekście nowego procesu potomnego.
- **Dokumentacja**: Więcej informacji można znaleźć w [manuale `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### Zachowanie `bash` i `sh` z SUID
- **`bash`**:
- Posiada opcję `-p`, która wpływa na traktowanie `euid` i `ruid`.
- Bez `-p`, `bash` ustawia `euid` na `ruid`, jeśli różnią się na początku.
- Z opcją `-p` zachowuje się zachowuje początkowy `euid`.
- Więcej szczegółów można znaleźć w [manuale `bash`](https://linux.die.net/man/1/bash).
- **`sh`**:
- Nie posiada mechanizmu podobnego do `-p` w `bash`.
- Zachowanie dotyczące identyfikatorów użytkownika nie jest wyraźnie opisane, z wyjątkiem opcji `-i`, podkreślającej zachowanie równości `euid` i `ruid`.
- Dodatkowe informacje są dostępne w [manuale `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Te mechanizmy, różniące się swoim działaniem, oferują wszechstronną gamę opcji wykonania i przejścia między programami, z konkretnymi niuansami w zarządzaniu i zachowaniu identyfikatorów użytkownika.

### Testowanie zachowań identyfikatorów użytkownika podczas wykonywania

Przykłady zaczerpnięte z https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, sprawdź je dla dalszych informacji

#### Przypadek 1: Użycie `setuid` z `system`

**Cel**: Zrozumienie efektu użycia `setuid` w połączeniu z `system` i `bash` jako `sh`.

**Kod C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Kompilacja i uprawnienia:**

Podczas kompilacji programu, system operacyjny nadaje mu pewne uprawnienia, które określają, jak program może być uruchamiany i przez kogo. Jednym z ważnych aspektów jest różnica między identyfikatorem użytkownika rzeczywistego (RUID), identyfikatorem użytkownika efektywnego (EUID) i identyfikatorem użytkownika zestawionego (SUID).

- **RUID (Real User ID):** RUID to identyfikator użytkownika, który jest przypisany do procesu, który go uruchamia. Jest to identyfikator użytkownika, który jest używany do określenia uprawnień dostępu do plików i zasobów systemowych.

- **EUID (Effective User ID):** EUID to identyfikator użytkownika, który jest używany przez proces podczas sprawdzania uprawnień dostępu. Jeśli EUID jest różny od RUID, oznacza to, że proces ma podwyższone uprawnienia.

- **SUID (Set User ID):** SUID to mechanizm, który pozwala procesowi działać z uprawnieniami innego użytkownika. Jeśli plik ma ustawiony bit SUID, to proces uruchamiany z tym plikiem będzie działał z uprawnieniami właściciela pliku, a nie z uprawnieniami użytkownika, który go uruchamia.

Właściwe zarządzanie uprawnieniami jest kluczowe dla zapewnienia bezpieczeństwa systemu. Niewłaściwe ustawienia uprawnień mogą prowadzić do eskalacji uprawnień, umożliwiając atakującemu uzyskanie większych uprawnień, niż powinien mieć. Dlatego ważne jest, aby regularnie sprawdzać i aktualizować uprawnienia plików oraz monitorować procesy, które mają podwyższone uprawnienia.
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

* `ruid` i `euid` początkowo mają wartości odpowiednio 99 (nobody) i 1000 (frank).
* `setuid` ustawia oba na 1000.
* `system` wykonuje polecenie `/bin/bash -c id` ze względu na symlink od sh do bash.
* `bash`, bez opcji `-p`, dostosowuje `euid` do `ruid`, co skutkuje oboma mającymi wartość 99 (nobody).

#### Przypadek 2: Użycie setreuid z systemem

**Kod C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Kompilacja i uprawnienia:**

Podczas kompilacji programu, system operacyjny nadaje mu pewne uprawnienia. Jednym z tych uprawnień jest identyfikator użytkownika (UID), który określa, do jakiego użytkownika należy program. Istnieje również identyfikator rzeczywisty użytkownika (RUID), który jest identyfikatorem użytkownika, który uruchomił program. 

Jeśli program ma ustawiony identyfikator użytkownika (SUID), oznacza to, że program będzie uruchamiany z uprawnieniami właściciela pliku, niezależnie od tego, kto go uruchomił. To może być przydatne w przypadku programów, które wymagają specjalnych uprawnień do wykonania określonych operacji.

Jednakże, jeśli program z ustawionym identyfikatorem użytkownika (SUID) zawiera błąd, to może być wykorzystane do eskalacji uprawnień. Atakujący może wykorzystać ten błąd, aby uruchomić kod z uprawnieniami właściciela pliku i uzyskać dostęp do funkcji systemowych, które normalnie są niedostępne dla zwykłego użytkownika.

Podobnie, jeśli program z ustawionym identyfikatorem użytkownika (SUID) jest podatny na atak przepełnienia bufora lub innego rodzaju ataku, atakujący może wykorzystać tę podatność do wykonania kodu z uprawnieniami właściciela pliku.

Dlatego ważne jest, aby starannie monitorować i zarządzać programami z ustawionym identyfikatorem użytkownika (SUID), aby zapobiec potencjalnym atakom eskalacji uprawnień.
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Wykonanie i wynik:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

* `setreuid` ustawia zarówno ruid, jak i euid na 1000.
* `system` wywołuje bash, który zachowuje identyfikatory użytkowników ze względu na ich równość, efektywnie działając jako frank.

#### Przypadek 3: Użycie setuid z execve
Cel: Badanie interakcji między setuid a execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Wykonanie i wynik:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

* `ruid` pozostaje 99, ale `euid` jest ustawione na 1000, zgodnie z efektem `setuid`.

**Przykład kodu C 2 (Wywołanie Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Wykonanie i wynik:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

* Chociaż `euid` jest ustawiane na 1000 przez `setuid`, `bash` resetuje euid na `ruid` (99) z powodu braku opcji `-p`.

**Przykład kodu C 3 (Używając bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Wykonanie i wynik:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Odwołania
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
