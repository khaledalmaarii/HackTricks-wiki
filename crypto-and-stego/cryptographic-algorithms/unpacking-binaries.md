{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
{% endhint %}


# Identyfikacja spakowanych binarek

* **brak ciągów**: Często można zauważyć, że spakowane binarki nie mają prawie żadnych ciągów
* Dużo **nieużywanych ciągów**: Również, gdy złośliwe oprogramowanie używa jakiegoś rodzaju komercyjnego pakera, często można znaleźć wiele ciągów bez odniesień krzyżowych. Nawet jeśli te ciągi istnieją, nie oznacza to, że binarka nie jest spakowana.
* Możesz również użyć kilku narzędzi, aby spróbować znaleźć, który paker został użyty do spakowania binarki:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Podstawowe zalecenia

* **Zacznij** analizować spakowaną binarkę **od dołu w IDA i przechodź w górę**. Rozpakowacze kończą działanie, gdy rozpakowany kod kończy działanie, więc mało prawdopodobne jest, że rozpakowacz przekazuje wykonanie do rozpakowanego kodu na początku.
* Szukaj **JMP-ów** lub **CALL-ów** do **rejestrów** lub **obszarów** **pamięci**. Szukaj również **funkcji przesyłających argumenty i adres, a następnie wywołujących `retn`**, ponieważ powrót z funkcji w takim przypadku może wywołać adres właśnie przesłany na stos przed jego wywołaniem.
* Umieść **punkt przerwania** na `VirtualAlloc`, ponieważ alokuje on miejsce w pamięci, gdzie program może zapisać rozpakowany kod. "Uruchom do kodu użytkownika" lub użyj F8, aby **uzyskać wartość wewnątrz EAX** po wykonaniu funkcji i "**podążaj za tym adresem w zrzucie**". Nigdy nie wiesz, czy to jest obszar, w którym rozpakowany kod zostanie zapisany.
* **`VirtualAlloc`** z wartością "**40**" jako argument oznacza Odczyt+Zapis+Wykonanie (jakiś kod, który wymaga wykonania, zostanie skopiowany tutaj).
* **Podczas rozpakowywania** kodu normalne jest znalezienie **wielu wywołań** do **operacji arytmetycznych** i funkcji takich jak **`memcopy`** lub **`Virtual`**`Alloc`. Jeśli znajdziesz się w funkcji, która najwyraźniej wykonuje tylko operacje arytmetyczne i może jakieś `memcopy`, zalecenie to spróbować **znaleźć koniec funkcji** (może JMP lub wywołanie do jakiegoś rejestru) **lub** przynajmniej **wywołanie ostatniej funkcji** i uruchomić do niej, ponieważ kod nie jest interesujący.
* Podczas rozpakowywania kodu **zauważaj**, kiedy **zmieniasz obszar pamięci**, ponieważ zmiana obszaru pamięci może wskazywać na **rozpoczęcie kodu rozpakowującego**. Możesz łatwo zrzucić obszar pamięci używając Process Hacker (proces --> właściwości --> pamięć).
* Podczas próby rozpakowania kodu dobrym sposobem na **sprawdzenie, czy już pracujesz z rozpakowanym kodem** (więc możesz go po prostu zrzucić) jest **sprawdzenie ciągów binarki**. Jeśli w pewnym momencie wykonasz skok (może zmieniając obszar pamięci) i zauważysz, że **dodano znacznie więcej ciągów**, wtedy możesz wiedzieć, że **pracujesz z rozpakowanym kodem**.\
Jednak, jeśli paker już zawiera wiele ciągów, możesz zobaczyć, ile ciągów zawiera słowo "http" i sprawdzić, czy ta liczba wzrasta.
* Gdy zrzucasz plik wykonywalny z obszaru pamięci, możesz naprawić niektóre nagłówki używając [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
</details>
{% endhint %}
