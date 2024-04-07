<details>

<summary><strong>Zacznij naukę hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>


# Identyfikacja spakowanych binariów

* **Brak ciągów znaków**: Często zdarza się, że spakowane binaria praktycznie nie zawierają żadnych ciągów znaków.
* Wiele **nieużywanych ciągów znaków**: Ponadto, gdy złośliwe oprogramowanie używa jakiegoś rodzaju komercyjnego pakera, często można znaleźć wiele ciągów znaków bez odwołań krzyżowych. Nawet jeśli te ciągi istnieją, nie oznacza to, że binarny plik nie jest spakowany.
* Możesz również użyć narzędzi do próby znalezienia, który paker został użyty do spakowania binariów:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Podstawowe zalecenia

* **Zacznij** analizować spakowany binarny **od dołu w IDA i idź w górę**. Unpackery kończą działanie, gdy kończy się kod rozpakowany, więc mało prawdopodobne jest, aby unpacker przekazał wykonanie do kodu rozpakowanego na początku.
* Szukaj **JMP** lub **CALLi** do **rejestrów** lub **obszarów** **pamięci**. Szukaj również **funkcji, które przekazują argumenty i adres kierunkowy, a następnie wywołują `retn`**, ponieważ zwrócenie funkcji w tym przypadku może wywołać adres właśnie dodany na stosie przed jego wywołaniem.
* Ustaw **punkt przerwania** na `VirtualAlloc`, ponieważ alokuje miejsce w pamięci, gdzie program może zapisać rozpakowany kod. "Uruchom do kodu użytkownika" lub użyj F8, aby **uzyskać wartość w EAX** po wykonaniu funkcji i "**śledź ten adres w zrzucie**". Nigdy nie wiesz, czy to jest obszar, w którym zostanie zapisany rozpakowany kod.
* **`VirtualAlloc`** z wartością "**40**" jako argument oznacza Read+Write+Execute (niektóry kod wymagający wykonania zostanie skopiowany tutaj).
* Podczas rozpakowywania kodu normalne jest znalezienie **kilku wywołań** operacji **arytmetycznych** i funkcji takich jak **`memcopy`** lub **`Virtual`**`Alloc`. Jeśli znajdziesz się w funkcji, która wydaje się wykonywać tylko operacje arytmetyczne i być może `memcopy`, zaleceniem jest spróbować **znaleźć koniec funkcji** (może to być JMP lub wywołanie do jakiegoś rejestru) **lub** przynajmniej **wywołanie ostatniej funkcji** i przejście do niej, ponieważ kod nie jest interesujący.
* Podczas rozpakowywania kodu **zauważ**, kiedy **zmieniasz obszar pamięci**, ponieważ zmiana obszaru pamięci może wskazywać na **początek kodu rozpakowywania**. Możesz łatwo zrzucić obszar pamięci, używając Process Hacker (proces --> właściwości --> pamięć).
* Próbując rozpakować kod, dobrym sposobem na **sprawdzenie, czy już pracujesz z rozpakowanym kodem** (aby go po prostu zrzucić), jest **sprawdzenie ciągów znaków binariów**. Jeśli w pewnym momencie wykonujesz skok (może zmieniając obszar pamięci) i zauważysz, że **dodano znacznie więcej ciągów znaków**, to możesz wiedzieć, **że pracujesz z rozpakowanym kodem**.\
Jednak jeśli pakowacz już zawiera wiele ciągów znaków, możesz sprawdzić, ile ciągów zawiera słowo "http" i zobaczyć, czy ta liczba wzrasta.
* Gdy zrzucasz wykonywalny plik z obszaru pamięci, możesz naprawić niektóre nagłówki za pomocą [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).


<details>

<summary><strong>Zacznij naukę hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
