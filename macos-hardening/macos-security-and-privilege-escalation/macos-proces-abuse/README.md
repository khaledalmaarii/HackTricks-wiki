# Nadużywanie procesów w systemie macOS

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Nadużywanie procesów w systemie macOS

System macOS, podobnie jak każdy inny system operacyjny, zapewnia różne metody i mechanizmy **interakcji, komunikacji i udostępniania danych** między procesami. Choć te techniki są niezbędne dla efektywnego funkcjonowania systemu, mogą być również wykorzystywane przez cyberprzestępców do **wykonywania szkodliwych działań**.

### Wstrzykiwanie bibliotek

Wstrzykiwanie bibliotek to technika, w której atakujący **wymusza na procesie załadowanie złośliwej biblioteki**. Po wstrzyknięciu biblioteka działa w kontekście docelowego procesu, zapewniając atakującemu takie same uprawnienia i dostęp jak proces.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Hookowanie funkcji

Hookowanie funkcji polega na **przechwytywaniu wywołań funkcji** lub wiadomości w kodzie oprogramowania. Poprzez hookowanie funkcji atakujący może **modyfikować zachowanie** procesu, obserwować poufne dane lub nawet przejąć kontrolę nad przebiegiem wykonywania.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Komunikacja międzyprocesowa

Komunikacja międzyprocesowa (IPC) odnosi się do różnych metod, za pomocą których oddzielne procesy **udostępniają i wymieniają dane**. Choć IPC jest niezbędne dla wielu legalnych aplikacji, może być również nadużywane do podważania izolacji procesów, wycieku poufnych informacji lub wykonywania nieautoryzowanych działań.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Wstrzykiwanie aplikacji Electron

Aplikacje Electron uruchamiane z określonymi zmiennymi środowiskowymi mogą być podatne na wstrzykiwanie procesów:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Brudne pliki NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** i ich interakcje w ramach aplikacji. Jednak mogą one **wykonywać dowolne polecenia** i **Gatekeeper nie powstrzymuje** już uruchomionej aplikacji przed ponownym uruchomieniem, jeśli plik NIB zostanie zmodyfikowany. Dlatego mogą być one wykorzystane do wykonania dowolnych programów:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Wstrzykiwanie aplikacji Java

Można nadużyć pewnych możliwości języka Java (takich jak zmienna środowiskowa **`_JAVA_OPTS`**) do wykonania przez aplikację Java **dowolnego kodu/polecenia**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie aplikacji .Net

Można wstrzykiwać kod do aplikacji .Net, **nadużywając funkcjonalności debugowania .Net** (niechronionych przez zabezpieczenia macOS, takie jak utwardzanie czasu wykonania).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie Perl

Sprawdź różne opcje, aby skrypt Perl wykonywał dowolny kod:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie Ruby

Można również nadużywać zmiennych środowiskowych Ruby do wykonania dowolnego kodu w skryptach:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie Pythona

Jeśli zmienna środowiskowa **`PYTHONINSPECT`** jest ustawiona, proces Pythona przejdzie do interaktywnego interfejsu wiersza poleceń Pythona po zakończeniu działania. Można również użyć **`PYTHONSTARTUP`**, aby wskazać skrypt Pythona do wykonania na początku sesji interaktywnej.\
Należy jednak zauważyć, że skrypt **`PYTHONSTARTUP`** nie zostanie wykonany, gdy **`PYTHONINSPECT`** tworzy sesję interaktywną.

Inne zmienne środowiskowe, takie jak **`PYTHONPATH`** i **`PYTHONHOME`**, mogą również być przydatne do wykonania dowolnego kodu w poleceniu Pythona.

Należy zauważyć, że pliki wykonywalne skompilowane za pomocą **`pyinstaller`** nie będą korzystać z tych zmiennych środowiskowych, nawet jeśli są uruchamiane za pomocą osadzonego Pythona.

{% hint style="danger" %}
Ogólnie rzecz biorąc, nie udało mi się znaleźć sposobu na wykonanie dowolnego kodu w Pythonie, nadużywając zmiennych środowiskowych.\
Jednak większość osób instaluje Pythona za pomocą **Hombrew**, który instaluje Pythona w **zapisywalnej lokalizacji** dla domyślnego użytkownika administratora. Można go przejąć za pomocą czegoś takiego jak:
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

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) to otwarte oprogramowanie, które może **wykrywać i blokować działania związane z wstrzykiwaniem procesów**:

* Korzystanie z **Zmiennych Środowiskowych**: Monitoruje obecność dowolnej z następujących zmiennych środowiskowych: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** i **`ELECTRON_RUN_AS_NODE`**
* Korzystanie z wywołań **`task_for_pid`**: Służy do znalezienia momentu, gdy jeden proces chce uzyskać **port zadania innego procesu**, co umożliwia wstrzyknięcie kodu do tego procesu.
* Parametry aplikacji **Electron**: Ktoś może użyć argumentów wiersza poleceń **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`** do uruchomienia aplikacji Electron w trybie debugowania i wstrzyknięcia do niej kodu.
* Korzystanie z **symlinków** lub **hardlinków**: Najczęstszym nadużyciem jest umieszczenie linku z uprawnieniami naszego użytkownika i skierowanie go do lokalizacji o wyższych uprawnieniach. Wykrywanie jest bardzo proste zarówno dla hardlinków, jak i symlinków. Jeśli proces tworzący link ma **inne poziomy uprawnień** niż plik docelowy, tworzymy **alert**. Niestety w przypadku symlinków blokowanie jest niemożliwe, ponieważ nie mamy informacji o miejscu docelowym linku przed jego utworzeniem. Jest to ograniczenie frameworka EndpointSecuriy firmy Apple.

### Wywołania dokonywane przez inne procesy

W [**tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) można znaleźć informacje na temat tego, jak można użyć funkcji **`task_name_for_pid`** do uzyskania informacji o innych **procesach wstrzykujących kod w proces** i następnie uzyskania informacji o tym innym procesie.

Należy zauważyć, że aby wywołać tę funkcję, musisz mieć **ten sam uid** co proces uruchamiający lub **root** (a funkcja zwraca informacje o procesie, a nie sposób wstrzyknięcia kodu).

## Odwołania

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Uzyskaj [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
