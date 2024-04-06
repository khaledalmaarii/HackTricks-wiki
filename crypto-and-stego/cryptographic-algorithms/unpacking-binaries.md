<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>


# Identyfikowanie spakowanych plików binarnych

* **Brak ciągów znaków**: Często zdarza się, że spakowane pliki binarne nie mają praktycznie żadnych ciągów znaków.
* Wiele **nieużywanych ciągów znaków**: Kiedy złośliwe oprogramowanie używa jakiegoś rodzaju komercyjnego pakera, często można znaleźć wiele ciągów znaków bez odwołań krzyżowych. Nawet jeśli te ciągi istnieją, nie oznacza to, że plik binarny nie jest spakowany.
* Można również użyć narzędzi, aby spróbować znaleźć pakera, który został użyty do spakowania pliku binarnego:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Podstawowe zalecenia

* **Zacznij** analizować spakowany plik binarny **od dołu w IDA i poruszaj się w górę**. Unpackery kończą działanie, gdy kończy się działanie rozpakowanego kodu, więc mało prawdopodobne jest, że unpacker przekaże wykonanie do rozpakowanego kodu na początku.
* Szukaj **JMP** lub **CALL** do **rejestrów** lub **obszarów** **pamięci**. Szukaj również **funkcji, które przekazują argumenty i adres kierunku, a następnie wywołują `retn`**, ponieważ zwrócenie funkcji w tym przypadku może wywołać adres, który został właśnie umieszczony na stosie przed jego wywołaniem.
* Ustaw **punkt przerwania** na `VirtualAlloc`, ponieważ to alokuje miejsce w pamięci, gdzie program może zapisywać rozpakowany kod. Uruchomienie do kodu użytkownika lub użycie F8, aby **uzyskać wartość w rejestrze EAX** po wykonaniu funkcji i "**śledź ten adres w dumpie**". Nigdy nie wiesz, czy to jest obszar, w którym zostanie zapisany rozpakowany kod.
* **`VirtualAlloc`** z wartością "**40**" jako argument oznacza Read+Write+Execute (jakikolwiek kod, który wymaga wykonania, zostanie tutaj skopiowany).
* Podczas rozpakowywania kodu normalne jest znalezienie **wielu wywołań** operacji arytmetycznych i funkcji takich jak **`memcopy`** lub **`Virtual`**`Alloc`. Jeśli znajdziesz się w funkcji, która wydaje się wykonywać tylko operacje arytmetyczne i być może kilka `memcopy`, zaleceniem jest próba **znalezienia końca funkcji** (może to być JMP lub wywołanie do jakiegoś rejestru) **lub przynajmniej wywołanie ostatniej funkcji** i uruchomienie do niej, ponieważ kod nie jest interesujący.
* Podczas rozpakowywania kodu **zwróć uwagę**, kiedy **zmieniasz obszar pamięci**, ponieważ zmiana obszaru pamięci może wskazywać **rozpoczęcie kodu rozpakowującego**. Możesz łatwo zrzucić obszar pamięci, używając Process Hacker (proces --> właściwości --> pamięć).
* Podczas próby rozpakowania kodu dobrym sposobem, aby **wiedzieć, czy już pracujesz z rozpakowanym kodem** (aby go po prostu zrzucić), jest **sprawdzenie ciągów znaków w pliku binarnym**. Jeśli w pewnym momencie wykonasz skok (może zmieniając obszar pamięci) i zauważysz, że **dodano dużo więcej ciągów znaków**, to możesz wiedzieć, że **pracujesz z rozpakowanym kodem**.\
Jednak jeśli pakiet zawiera już wiele ciągów znaków, możesz sprawdzić, ile ciągów zawiera słowo "http" i sprawdzić, czy ta liczba wzrasta.
* Gdy zrzucasz plik wykonywalny z obszaru pamięci, możesz naprawić niektóre nagłówki za pomocą [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).


<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
