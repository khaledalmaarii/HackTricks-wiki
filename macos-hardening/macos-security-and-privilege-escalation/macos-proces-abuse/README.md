# macOS Proces Abuse

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Nadużycie procesów w macOS

macOS, podobnie jak każdy inny system operacyjny, zapewnia różne metody i mechanizmy, dzięki którym **procesy mogą ze sobą współdziałać, komunikować się i dzielić danymi**. Choć te techniki są niezbędne dla efektywnego funkcjonowania systemu, mogą być również wykorzystywane przez sprawców zagrożeń do **wykonywania działań o charakterze złośliwym**.

### Wstrzykiwanie Bibliotek

Wstrzykiwanie Bibliotek to technika, w której atakujący **zmusza proces do załadowania złośliwej biblioteki**. Po wstrzyknięciu biblioteka działa w kontekście docelowego procesu, zapewniając atakującemu takie same uprawnienia i dostęp jak proces.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Hacowanie Funkcji

Hacowanie Funkcji polega na **przechwytywaniu wywołań funkcji** lub komunikatów w kodzie oprogramowania. Poprzez hacowanie funkcji atakujący może **modyfikować zachowanie** procesu, obserwować wrażliwe dane, a nawet uzyskać kontrolę nad przepływem wykonania.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md](macos-function-hooking.md)
{% endcontent-ref %}

### Komunikacja Międzyprocesowa

Komunikacja Międzyprocesowa (IPC) odnosi się do różnych metod, za pomocą których oddzielne procesy **dzielą się i wymieniają danymi**. Choć IPC jest fundamentalny dla wielu legalnych aplikacji, może być również nadużywany do omijania izolacji procesów, ujawniania wrażliwych informacji lub wykonywania nieautoryzowanych działań.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Wstrzykiwanie Aplikacji Electron

Aplikacje Electron uruchamiane z określonymi zmiennymi środowiskowymi mogą być podatne na wstrzykiwanie procesów:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie Chromium

Możliwe jest użycie flag `--load-extension` i `--use-fake-ui-for-media-stream` do przeprowadzenia **ataków typu man in the browser**, umożliwiających kradzież naciśnięć klawiszy, ruchu sieciowego, plików cookie, wstrzykiwanie skryptów na stronach...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### Brudne NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** i ich interakcje w ramach aplikacji. Jednak mogą **wykonywać dowolne polecenia** i **Gatekeeper nie blokuje** już uruchomionej aplikacji przed ponownym uruchomieniem, jeśli plik NIB zostanie zmodyfikowany. Dlatego mogą być wykorzystane do uruchamiania dowolnych programów w celu wykonania dowolnych poleceń:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Wstrzykiwanie Aplikacji Java

Możliwe jest nadużycie pewnych możliwości Javy (takich jak zmienna środowiskowa **`_JAVA_OPTS`**) do zmuszenia aplikacji Javy do wykonania **dowolnego kodu/polecenia**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie Aplikacji .Net

Możliwe jest wstrzykiwanie kodu do aplikacji .Net poprzez **nadużycie funkcjonalności debugowania .Net** (niechronionej przez zabezpieczenia macOS, takie jak utwardzanie czasu wykonania).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie Perla

Sprawdź różne opcje, aby skrypt Perl wykonał dowolny kod w:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie Ruby

Możliwe jest również nadużycie zmiennych środowiskowych Ruby do wykonania dowolnych skryptów:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie Pythona

Jeśli zmienna środowiskowa **`PYTHONINSPECT`** jest ustawiona, proces Pythona przejdzie do interaktywnej konsoli Pythona po zakończeniu. Można również użyć **`PYTHONSTARTUP`** do wskazania skryptu Pythona do wykonania na początku sesji interaktywnej.\
Należy jednak zauważyć, że skrypt **`PYTHONSTARTUP`** nie zostanie wykonany, gdy **`PYTHONINSPECT`** tworzy sesję interaktywną.

Inne zmienne środowiskowe, takie jak **`PYTHONPATH`** i **`PYTHONHOME`**, mogą również być przydatne do wykonania dowolnego kodu za pomocą polecenia Pythona.

Należy pamiętać, że pliki wykonywalne skompilowane za pomocą **`pyinstaller`** nie będą korzystać z tych zmiennych środowiskowych, nawet jeśli są uruchamiane za pomocą osadzonego Pythona.

{% hint style="danger" %}
Ogólnie rzecz biorąc, nie udało mi się znaleźć sposobu na zmuszenie Pythona do wykonania dowolnego kodu, nadużywając zmiennych środowiskowych.\
Jednak większość osób instaluje Pythona za pomocą **Hombrew**, który zainstaluje Pythona w **zapisywalnej lokalizacji** dla domyślnego użytkownika admina. Możesz go przejąć, wykonując coś w stylu:

```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```

Nawet **root** uruchomi ten kod podczas uruchamiania pythona.
{% endhint %}

## Wykrywanie

### Tarcza

[**Tarcza**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) to aplikacja typu open source, która może **wykrywać i blokować działania związane z wstrzykiwaniem procesów**:

* Korzystanie z **Zmiennych Środowiskowych**: Będzie monitorować obecność dowolnej z następujących zmiennych środowiskowych: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** oraz **`ELECTRON_RUN_AS_NODE`**
* Korzystanie z wywołań **`task_for_pid`**: Aby znaleźć, kiedy jeden proces chce uzyskać **port zadania innego**, co pozwala na wstrzyknięcie kodu do procesu.
* **Parametry aplikacji Electron**: Ktoś może użyć argumentów wiersza poleceń **`--inspect`**, **`--inspect-brk`** oraz **`--remote-debugging-port`** do uruchomienia aplikacji Electron w trybie debugowania, co umożliwia wstrzyknięcie kodu do niej.
* Korzystanie z **symlinków** lub **hardlinków**: Zwykle najczęstszym nadużyciem jest **umieszczenie linku z uprawnieniami naszego użytkownika** i **skierowanie go do lokalizacji z wyższymi uprawnieniami**. Wykrycie jest bardzo proste zarówno dla hardlinków, jak i symlinków. Jeśli proces tworzący link ma **inne poziomy uprawnień** niż plik docelowy, tworzymy **alert**. Niestety w przypadku symlinków blokowanie nie jest możliwe, ponieważ nie mamy informacji o miejscu docelowym linku przed jego utworzeniem. Jest to ograniczenie frameworka EndpointSecuriy firmy Apple.

### Wywołania dokonywane przez inne procesy

W [**tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) można dowiedzieć się, jak można użyć funkcji **`task_name_for_pid`** do uzyskania informacji o innych **procesach wstrzykujących kod w proces** i uzyskania informacji o tym innym procesie.

Należy zauważyć, że aby wywołać tę funkcję, musisz być **tym samym uid** co proces uruchamiający lub **root** (i zwraca informacje o procesie, a nie sposób wstrzyknięcia kodu).

## Odnośniki

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFTów**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
