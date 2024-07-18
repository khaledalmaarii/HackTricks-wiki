{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępniaj sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) oraz [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>Prawa autorskie © Carlos Polop 2021.  Z wyjątkiem przypadków określonych inaczej (informacje zewnętrzne skopiowane do książki należą do pierwotnych autorów), tekst na stronie <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a> autorstwa Carlosa Polopa jest licencjonowany na podstawie <a href="https://creativecommons.org/licenses/by-nc/4.0/">Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)</a>.

Licencja: Uznanie autorstwa-Użycie niekomercyjne 4.0 Międzynarodowe (CC BY-NC 4.0)<br>
Licencja w języku zrozumiałym dla ludzi: https://creativecommons.org/licenses/by-nc/4.0/<br>
Pełne warunki prawne: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
Formatowanie: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# creative commons

# Uznanie autorstwa-Użycie niekomercyjne 4.0 Międzynarodowe

Korporacja Creative Commons ("Creative Commons") nie jest kancelarią prawną i nie świadczy usług prawnych ani porad prawnych. Rozpowszechnianie publicznych licencji Creative Commons nie tworzy relacji prawniczej między prawnikiem a klientem ani innego rodzaju relacji. Creative Commons udostępnia swoje licencje i związane z nimi informacje "w stanie istniejącym". Creative Commons nie daje żadnych gwarancji dotyczących swoich licencji, materiałów licencjonowanych na ich podstawie ani związanych z nimi informacji. Creative Commons odrzuca wszelką odpowiedzialność za szkody wynikające z ich użycia w największym możliwym zakresie.

## Korzystanie z publicznych licencji Creative Commons

Publiczne licencje Creative Commons zawierają standardowy zestaw warunków, które twórcy i inni posiadacze praw mogą stosować do udostępniania oryginalnych utworów autorskich i innych materiałów podlegających prawu autorskiemu oraz pewnym innym prawom określonym w poniższej licencji publicznej. Poniższe rozważania mają charakter informacyjny, nie są wyczerpujące i nie stanowią części naszych licencji.

* __Rozważania dla licencjodawców:__ Nasze publiczne licencje są przeznaczone do użytku przez osoby upoważnione do udzielenia publicznej zgody na korzystanie z materiału w sposób w inny sposób ograniczony przez prawo autorskie i pewne inne prawa. Nasze licencje są nieodwołalne. Licencjodawcy powinni przeczytać i zrozumieć warunki wybranej przez siebie licencji przed jej zastosowaniem. Licencjodawcy powinni również uzyskać wszystkie niezbędne prawa przed zastosowaniem naszych licencji, aby publiczność mogła ponownie wykorzystać materiał zgodnie z oczekiwaniami. Licencjodawcy powinni wyraźnie oznaczyć wszelkie materiały niepodlegające licencji. Dotyczy to innych materiałów licencjonowanych przez CC lub materiałów używanych na podstawie wyjątku lub ograniczenia prawa autorskiego. [Więcej rozważań dla licencjodawców](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __Rozważania dla publiczności:__ Korzystając z jednej z naszych publicznych licencji, licencjodawca udziela publiczności zgody na korzystanie z licencjonowanego materiału na określonych warunkach. Jeśli zgoda licencjodawcy nie jest konieczna z jakiegokolwiek powodu - na przykład z powodu jakiegokolwiek stosownego wyjątku lub ograniczenia prawa autorskiego - to takie korzystanie nie podlega regulacji licencji. Nasze licencje przyznają jedynie uprawnienia w zakresie prawa autorskiego i pewnych innych praw, których licencjodawca ma prawo udzielić. Korzystanie z licencjonowanego materiału może nadal być ograniczone z innych powodów, między innymi dlatego, że inni posiadają prawa autorskie lub inne prawa do materiału. Licencjodawca może zgłaszać specjalne prośby, na przykład żądając, aby wszystkie zmiany były oznaczone lub opisane. Chociaż nie jest to wymagane przez nasze licencje, zachęcamy do szanowania tych żądań w miarę możliwości. [Więcej rozważań dla publiczności](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# Creative Commons Attribution-NonCommercial 4.0 International Public License

Korzystając z Praw (zdefiniowanych poniżej), akceptujesz i zgadzasz się być związany warunkami tej Creative Commons Attribution-NonCommercial 4.0 International Public License ("Public License"). W miarę możliwości ta Public License może być interpretowana jako umowa, na mocy której otrzymujesz Prawa w zamian za akceptację tych warunków, a Licencjodawca udziela Ci takich praw w zamian za korzyści, jakie otrzymuje z udostępnienia Licencjonowanego Materiału na podanych warunkach.

## Sekcja 1 – Definicje.

a. __Materiał Przetworzony__ oznacza materiał podlegający Prawom Autorskim i Prawom Pokrewnym, który pochodzi z Licencjonowanego Materiału i w którym Licencjonowany Materiał jest tłumaczony, zmieniany, aranżowany, przekształcany lub w inny sposób modyfikowany w sposób wymagający zgody z tytułu Praw Autorskich i Praw Pokrewnych przysługujących Licencjodawcy. W ramach tej Public License, gdy Licencjonowany Materiał jest utworem muzycznym, wykonaniem lub nagraniem dźwiękowym, Materiał Przetworzony zawsze powstaje, gdy Licencjonowany Materiał jest synchronizowany w związku czasowym z obrazem ruchomym.

b. __Licencja Przetwórcy__ oznacza licencję, którą stosujesz do Twoich Praw Autorskich i Praw Pokrewnych w Twoich wkładach do Materiału Przetworzonego zgodnie z warunkami tej Public License.

c. __Prawa Autorskie i Prawa Pokrewne__ oznaczają prawa autorskie i/lub pokrewne ściśle związane z prawem autorskim, w tym, między innymi, prawa do wykonania, nadawania, nagrania dźwiękowego oraz Prawa Bazy Danych Sui Generis, bez względu na to, jak są one oznaczone lub sklasyfikowane. W ramach tej Public License, prawa określone w Sekcji 2(b)(1)-(2) nie są Prawami Autorskimi i Prawami Pokrewnymi.

d. __Skuteczne Środki Techniczne__ oznaczają środki, które w przypadku braku odpowiedniego upoważnienia nie mogą być obejśczone zgodnie z przepisami wypełniającymi zobowiązania wynikające z Artykułu 11 Traktatu WIPO o Prawie Autorskim przyjętego 20 grudnia 1996 r. oraz/lub podobnych międzynarodowych porozumień.

e. __Wyjątki i Ograniczenia__ oznaczają dozwolony użytek, sprawiedliwe wykorzystanie i/lub jakikolwiek inny wyjątek lub ograniczenie do Praw Autorskich i Praw Pokrewnych, które mają zastosowanie do Twojego korzystania z Licencjonowanego Materiału.

f. __Licencjonowany Materiał__ oznacza utwór artystyczny lub literacki, bazę danych lub inny materiał, do którego Licencjodawca zastosował tę Public License.

g. __Prawa Licencjonowanego__ oznaczają prawa udzielone Tobie na podstawie warunków tej Public License, które są ograniczone do wszystkich Praw Autorskich i Praw Pokrewnych mających zastosowanie do Twojego korzystania z Licencjonowanego Materiału i których Licencjodawca ma uprawnienie do licencjonowania.

h. __Licencjodawca__ oznacza osobę lub podmiot udzielający praw na podstawie tej Public License.

i. __Niekomercyjne__ oznacza nieprzewidujące przede wszystkim korzyści komercyjnych ani wynagrodzenia pieniężnego. W ramach tej Public License, wymiana Licencjonowanego Materiału na inny materiał podlegający Prawom Autorskim i Prawom Pokrewnym za pośrednictwem udostępniania plików cyfrowych lub podobnych środków jest uznawana za działalność niekomercyjną, pod warunkiem, że nie ma żadnych płatności wynagrodzenia pieniężnego związanych z wymianą.

j. __Udostępnianie__ oznacza udostępnianie materiału publiczności w dowolny sposób lub procesem, który wymaga zgody z tytułu Praw Licencjonowanych, takich jak reprodukcja, publiczne wyświetlanie, publiczne wykonanie, dystrybucja, rozpowszechnianie, komunikacja lub import, oraz udostępnianie materiału publiczności, w tym w taki sposób, aby członkowie publiczności mogli uzyskać dostęp do materiału z miejsca i w czasie wybranym przez nich indywidualnie.

k. __Prawa Bazy Danych Sui Generis__ oznaczają prawa inne niż prawa autorskie wynikające z Dyrektywy 96/9/WE Parlamentu Europejskiego i Rady z dnia 11 marca 1996 r. w sprawie ochrony prawnej baz danych, zmienionej i/lub zastąpionej, a także inne istotnie równoważne prawa gdziekolwiek na świecie.

l. __Ty__ oznacza osobę lub podmiot korzystający z Praw Licencjonowanych na podstawie tej Public License. "Twój" ma odpowiednie znaczenie.
## Sekcja 2 – Zakres.

a. ___Przyznanie licencji.___

1. Zgodnie z warunkami niniejszej Licencji Publicznej, Licencjodawca niniejszym udziela Tobie licencji na wykonywanie Praw Licencjonowanych w Materiałach Licencjonowanych na całym świecie, bezpłatnej, nieprzenoszalnej, nieekskluzywnej, nieodwołalnej licencji do:

A. reprodukowania i Udostępniania Materiałów Licencjonowanych, w całości lub w części, wyłącznie w celach niekomercyjnych; oraz

B. tworzenia, reprodukowania i Udostępniania Materiałów Przetworzonych wyłącznie w celach niekomercyjnych.

2. __Wyjątki i Ograniczenia.__ Dla jasności, gdy Wyjątki i Ograniczenia mają zastosowanie do Twojego użytku, niniejsza Licencja Publiczna nie obowiązuje, i nie musisz przestrzegać jej warunków.

3. __Okres.__ Okres obowiązywania niniejszej Licencji Publicznej jest określony w sekcji 6(a).

4. __Media i formaty; dozwolone modyfikacje techniczne.__ Licencjodawca upoważnia Cię do korzystania z Praw Licencjonowanych we wszystkich mediach i formatach, zarówno obecnie znanych, jak i stworzonych w przyszłości, oraz do dokonywania niezbędnych modyfikacji technicznych w tym celu. Licencjodawca zrzeka się i/lub zgadza się nie twierdzić, że posiada prawo lub uprawnienie do zakazu dokonywania modyfikacji technicznych koniecznych do korzystania z Praw Licencjonowanych, w tym modyfikacji technicznych koniecznych do obejścia Skutecznych Środków Technicznych. W ramach niniejszej Licencji Publicznej, dokonywanie modyfikacji upoważnionych przez tę sekcję 2(a)(4) nigdy nie prowadzi do powstania Materiałów Przetworzonych.

5. __Odbiorcy wtórni.__

A. __Oferta od Licencjodawcy – Materiały Licencjonowane.__ Każdy odbiorca Materiałów Licencjonowanych automatycznie otrzymuje ofertę od Licencjodawcy do korzystania z Praw Licencjonowanych na warunkach określonych w niniejszej Licencji Publicznej.

B. __Brak dodatkowych ograniczeń dla odbiorców wtórnych.__ Nie możesz oferować ani narzucać dodatkowych lub innych warunków lub stosować Skutecznych Środków Technicznych do Materiałów Licencjonowanych, jeśli uniemożliwia to korzystanie z Praw Licencjonowanych przez jakiegokolwiek odbiorcę Materiałów Licencjonowanych.

6. __Brak poparcia.__ Nic w niniejszej Licencji Publicznej nie stanowi ani nie może być interpretowane jako zgoda na twierdzenie lub sugerowanie, że Ty jesteś, lub że Twoje korzystanie z Materiałów Licencjonowanych jest związane z, lub jest sponsorowane, popierane lub posiada oficjalny status przyznanego przez Licencjodawcę lub inne osoby wyznaczone do otrzymywania atrybucji, zgodnie z postanowieniami sekcji 3(a)(1)(A)(i).

b. ___Inne prawa.___

1. Prawa osobiste, takie jak prawo do integralności, nie są objęte licencją w ramach niniejszej Licencji Publicznej, ani nie są objęte prawami do wizerunku, prywatności i/lub innymi podobnymi prawami osobistymi; jednakże, w miarę możliwości, Licencjodawca zrzeka się i/lub zgadza się nie twierdzić o posiadaniu takich praw przez Licencjodawcę w ograniczonym zakresie koniecznym do umożliwienia Tobie korzystania z Praw Licencjonowanych, lecz nie dalej.

2. Prawa patentowe i znakowe nie są objęte licencją w ramach niniejszej Licencji Publicznej.

3. W miarę możliwości, Licencjodawca zrzeka się prawa do pobierania tantiem od Ciebie za korzystanie z Praw Licencjonowanych, bezpośrednio lub poprzez organizację zbierającą opłaty na podstawie dobrowolnego lub ustawowego systemu licencjonowania możliwego do zrzeczenia się. W pozostałych przypadkach Licencjodawca wyraźnie zastrzega sobie prawo do pobierania takich tantiem, również gdy Materiały Licencjonowane są używane w innych celach niż niekomercyjne.

## Sekcja 3 – Warunki Licencji.

Twoje korzystanie z Praw Licencjonowanych jest wyraźnie uzależnione od spełnienia następujących warunków.

a. ___Atrybucja.___

1. Jeśli Udostępniasz Materiały Licencjonowane (w tym w formie zmodyfikowanej), musisz:

A. zachować następujące elementy, jeśli zostały dostarczone przez Licencjodawcę wraz z Materiałami Licencjonowanymi:

i. identyfikację twórców Materiałów Licencjonowanych i innych osób wyznaczonych do otrzymania atrybucji, w dowolny rozsądny sposób żądany przez Licencjodawcę (w tym pod pseudonimem, jeśli jest wyznaczony);

ii. oznaczenie praw autorskich;

iii. oznaczenie odnoszące się do niniejszej Licencji Publicznej;

iv. oznaczenie odnoszące się do wyłączenia gwarancji;

v. URI lub hiperłącze do Materiałów Licencjonowanych, w miarę możliwości;

B. wskazać, jeśli zmodyfikowałeś Materiały Licencjonowane i zachować wskazanie wszelkich poprzednich modyfikacji; oraz

C. wskazać, że Materiały Licencjonowane są objęte niniejszą Licencją Publiczną, i zawrzeć tekst lub URI lub hiperłącze do niniejszej Licencji Publicznej.

2. Możesz spełnić warunki określone w sekcji 3(a)(1) w dowolny rozsądny sposób, zgodnie z medium, środkami i kontekstem, w którym Udostępniasz Materiały Licencjonowane. Na przykład, może być rozsądne spełnienie warunków poprzez udostępnienie URI lub hiperłącza do zasobu zawierającego wymagane informacje.

3. Jeśli Licencjodawca tego żąda, musisz usunąć wszelkie informacje wymagane zgodnie z sekcją 3(a)(1)(A) w miarę możliwości.

4. Jeśli Udostępniasz Materiały Przetworzone, których jesteś autorem, zastosowana przez Ciebie Licencja Adaptera nie może uniemożliwiać odbiorcom Materiałów Przetworzonych spełnienia warunków niniejszej Licencji Publicznej.

## Sekcja 4 – Prawa Bazy Danych Sui Generis.

Jeśli Prawa Licencjonowane obejmują Prawa Bazy Danych Sui Generis, które mają zastosowanie do Twojego korzystania z Materiałów Licencjonowanych:

a. dla jasności, sekcja 2(a)(1) przyznaje Tobie prawo do wydobywania, ponownego wykorzystywania, reprodukowania i Udostępniania całej lub znacznej części treści bazy danych wyłącznie w celach niekomercyjnych;

b. jeśli zawierasz całą lub znaczną część treści bazy danych w bazie danych, w której posiadasz Prawa Bazy Danych Sui Generis, to baza danych, w której posiadasz Prawa Bazy Danych Sui Generis (ale nie jej poszczególne treści) stanowi Materiał Przetworzony; oraz

c. musisz spełnić warunki określone w sekcji 3(a), jeśli Udostępniasz całą lub znaczną część treści bazy danych.

Dla jasności, ta sekcja 4 uzupełnia, a nie zastępuje Twoich obowiązków wynikających z niniejszej Licencji Publicznej, gdy Prawa Licencjonowane obejmują inne Prawa Autorskie i Pokrewne.

## Sekcja 5 – Wyłączenie Gwarancji i Ograniczenie Odpowiedzialności.

a. __O ile Licencjodawca nie zobowiąże się osobno, w miarę możliwości, Licencjodawca udostępnia Materiały Licencjonowane "takie jak są" i "takie jak są dostępne", i nie udziela żadnych gwarancji jakiegokolwiek rodzaju dotyczących Materiałów Licencjonowanych, czy to wyraźnych, dorozumianych, ustawowych, czy innych. Obejmuje to, między innymi, gwarancje tytułu, przydatności handlowej, przydatności do określonego celu, niezawodności, braku naruszenia praw, braku ukrytych lub innych wad, dokładności, lub obecności lub braku błędów, czy to znanych, czy odkrywalnych. Gdzie wyłączenia gwarancji nie są dozwolone w całości lub w części, niniejsze wyłączenie gwarancji może nie mieć zastosowania do Ciebie.__

b. __O ile to możliwe, w żadnym wypadku Licencjodawca nie będzie ponosić wobec Ciebie odpowiedzialności na żadnej podstawie prawnej (w tym, między innymi, z tytułu zaniedbania) lub w inny sposób za jakiekolwiek bezpośrednie, specjalne, pośrednie, przypadkowe, wtórne, karygodne, wzorcowe lub inne straty, koszty, wydatki lub szkody wynikające z niniejszej Licencji Publicznej lub korzystania z Materiałów Licencjonowanych, nawet jeśli Licencjodawca został poinformowany o możliwości wystąpienia takich strat, kosztów, wydatków lub szkód. Gdzie ograniczenia odpowiedzialności nie są dozwolone w całości lub w części, to ograniczenie może nie mieć zastosowania do Ciebie.__

c. Wyłączenie gwarancji i ograniczenie odpowiedzialności określone powyżej powinny być interpretowane w sposób, który, o ile to możliwe, najbardziej zbliża się do bezwzględnego wyłączenia i zrzeczenia się wszelkiej odpowiedzialności.

## Sekcja 6 – Okres i Rozwiązanie.

a. Niniejsza Licencja Publiczna obowiązuje przez okres Praw Autorskich i Pokrewnych udzielonych tutaj. Jednakże, jeśli nie będziesz przestrzegać niniejszej Licencji Publicznej, Twoje prawa wynikające z niniejszej Licencji Publicznej ulegną automatycznemu wygaśnięciu.

b. Gdy Twoje prawo do korzystania z Materiałów Licencjonowanych wygasa zgodnie z sekcją 6(a), zostaje ono przywrócone:

1. automatycznie od daty naprawienia naruszenia, o ile zostanie ono naprawione w ciągu 30 dni od odkrycia naruszenia; lub

2. na podstawie wyraźnego przywrócenia przez Licencjodawcę.

Dla jasności, ta sekcja 6(b) nie wpływa na prawo Licencjodawcy do dochodzenia środków zaradczych za Twoje naruszenia niniejszej Licencji Publicznej.

c. Dla jasności, Licencjodawca może również oferować Materiały Licencjonowane na osobnych warunkach lub przestawać je dystrybuować w dowolnym momencie; jednakże, czyniąc to nie spowoduje rozwiązania niniejszej Licencji Publicznej.

d. Sekcje 1, 5, 6, 7 i 8 pozostają w mocy po rozwiązaniu niniejszej Licencji Publicznej.
## Sekcja 7 – Inne Warunki i Postanowienia.

a. Licencjodawca nie będzie związany żadnymi dodatkowymi lub innymi warunkami przekazanymi przez Ciebie, chyba że wyraźnie się zgodzi.

b. Wszelkie ustalenia, porozumienia lub umowy dotyczące Materiału Licencyjnego, które nie zostały wymienione w niniejszym dokumencie, są oddzielne od warunków tego Licencjonowania Publicznego.

## Sekcja 8 – Interpretacja.

a. Dla jasności, niniejsza Licencja Publiczna nie ogranicza, nie zawęża, nie ogranicza ani nie nakłada warunków na żadne wykorzystanie Materiału Licencyjnego, które mogłoby być legalnie dokonane bez zgody w ramach tej Licencji Publicznej.

b. W miarę możliwości, jeśli jakiekolwiek postanowienie niniejszej Licencji Publicznej zostanie uznane za niewykonalne, automatycznie zostanie ono dostosowane do minimalnego stopnia koniecznego do jego wykonalności. Jeśli postanowienie nie może zostać dostosowane, zostanie ono odłączone od tej Licencji Publicznej, nie wpływając na wykonalność pozostałych warunków.

c. Żaden warunek niniejszej Licencji Publicznej nie będzie uznany za zrzeczenie się, ani nie zostanie wyrażona zgoda na niewykonanie, chyba że wyraźnie zgodzi się na to Licencjodawca.

d. Nic w niniejszej Licencji Publicznej nie stanowi ani nie może być interpretowane jako ograniczenie lub zrzeczenie się jakichkolwiek przywilejów i immunitetów, które przysługują Licencjodawcy lub Tobie, w tym w odniesieniu do procesów prawnych jakiejkolwiek jurysdykcji lub władzy.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
{% hint style="success" %}
Ucz się i praktykuj Hacking AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcji**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępniaj sztuczki hackingu, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
