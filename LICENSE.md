<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Licencja Creative Commons" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>Prawa autorskie © Carlos Polop 2021. Chyba że wskazano inaczej (informacje zewnętrzne skopiowane do książki należą do pierwotnych autorów), tekst na stronie <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a> autorstwa Carlosa Polopa jest licencjonowany na podstawie <a href="https://creativecommons.org/licenses/by-nc/4.0/">Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)</a>.

Licencja: Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)<br>
Licencja czytelna dla człowieka: https://creativecommons.org/licenses/by-nc/4.0/<br>
Pełne warunki prawne: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
Formatowanie: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# creative commons

# Creative Commons Attribution-NonCommercial 4.0 International

Korporacja Creative Commons ("Creative Commons") nie jest kancelarią prawną i nie świadczy usług prawnych ani porad prawnych. Dystrybucja publicznych licencji Creative Commons nie tworzy stosunku prawnika-klienta ani innego stosunku. Creative Commons udostępnia swoje licencje i związane z nimi informacje "w stanie, w jakim się znajdują". Creative Commons nie udziela żadnych gwarancji dotyczących swoich licencji, jakiejkolwiek materiałów licencjonowanych na ich podstawie ani jakichkolwiek związanych z nimi informacji. Creative Commons nie ponosi żadnej odpowiedzialności za szkody wynikające z ich użycia w największym możliwym zakresie.

## Korzystanie z publicznych licencji Creative Commons

Publiczne licencje Creative Commons zawierają standardowy zestaw warunków, które twórcy i inni posiadacze praw mogą stosować do udostępniania oryginalnych utworów autorskich i innych materiałów objętych prawem autorskim oraz określonych innych praw w ramach licencji publicznej przedstawionej poniżej. Poniższe rozważania mają charakter informacyjny, nie są wyczerpujące i nie stanowią części naszych licencji.

* __Rozważania dla licencjodawców:__ Nasze publiczne licencje są przeznaczone do użytku przez osoby upoważnione do udzielania publicznej zgody na korzystanie z materiałów w sposób ograniczony przez prawa autorskie i określone inne prawa. Nasze licencje są nieodwołalne. Licencjodawcy powinni zapoznać się z warunkami wybranej przez siebie licencji przed jej zastosowaniem. Licencjodawcy powinni również uzyskać wszystkie niezbędne prawa przed zastosowaniem naszych licencji, aby publiczność mogła ponownie wykorzystać materiał zgodnie z oczekiwaniami. Licencjodawcy powinni wyraźnie oznaczyć wszelkie materiały niepodlegające licencji. Dotyczy to innych materiałów licencjonowanych przez CC lub materiałów używanych na podstawie wyjątku lub ograniczenia prawa autorskiego. [Więcej rozważań dla licencjodawców](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __Rozważania dla publiczności:__ Korzystając z jednej z naszych publicznych licencji, licencjodawca udziela publiczności zgody na korzystanie z licencjonowanego materiału zgodnie z określonymi warunkami. Jeśli zgoda licencjodawcy nie jest konieczna z jakiegokolwiek powodu - na przykład z powodu dowolnego zastosowania wyjątku lub ograniczenia prawa autorskiego - takie korzystanie nie podlega regulacjom licencji. Nasze licencje udzielają jedynie uprawnień w zakresie praw autorskich i określonych innych praw, które licencjodawca ma prawo udzielić. Korzystanie z licencjonowanego materiału może nadal być ograniczone z innych powodów, w tym dlatego, że inni mają prawa autorskie lub inne prawa do materiału. Licencjodawca może zgłaszać specjalne żądania, na przykład żądanie oznaczenia lub opisu wszystkich zmian. Chociaż nasze licencje nie wymagają tego, zachęcamy do szanowania tych żądań w miarę możliwości. [Więcej rozważań dla publiczności](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# Creative Commons Attribution-NonCommercial 4.0 International Public License

Korzystając z Licencjonowanych Praw (zdefiniowanych poniżej), akceptujesz i zgadzasz się być związany warunkami tej Creative Commons Attribution-NonCommercial 4.0 International Public License ("Licencja Publiczna"). W zakresie, w jakim ta Licencja Publiczna może być interpretowana jako umowa, otrzymujesz Licencjonowane Prawa w zamian za akceptację tych warunków, a Licencjodawca udziela Ci takich praw w zamian za korzyści, jakie otrzymuje od udostępnienia Licencjonowanego Materiału na podstawie tych warunków.

## Sekcja 1 - Definicje.

a. __Materiał Przekształcony__ oznacza materiał objęty prawami autorskimi i podobnymi prawami, który jest pochodny lub oparty na Licencjonowanym Materiale i w którym Licencjonowany Materiał jest tłumaczony, zmieniany, aranżowany, przekształcany lub w inny sposób modyfikowany w sposób wymagający zgody na podstawie praw autorskich i podobnych praw posiadanych przez Licencjodawcę. W przypadku tej Licencji Publicznej, jeśli Licencjonowany Materiał jest utworem muzycznym, wykonaniem lub nagraniem dźwiękowym, Materiał
## Sekcja 2 – Zakres.

a. ___Przyznanie licencji.___

1. Zgodnie z warunkami tej Licencji Publicznej, Licencjodawca niniejszym udziela Tobie na całym świecie, bezpłatnej, nieprzenoszalnej, nie wyłącznej, nieodwołalnej licencji do korzystania z Praw Licencjonowanych w Materiałach Licencjonowanych w celu:

A. reprodukcji i Udostępniania Materiałów Licencjonowanych, w całości lub w części, wyłącznie w celach niekomercyjnych; oraz

B. produkcji, reprodukcji i Udostępniania Materiałów Przystosowanych wyłącznie w celach niekomercyjnych.

2. __Wyjątki i ograniczenia.__ Dla uniknięcia wątpliwości, w przypadku gdy Wyjątki i Ograniczenia mają zastosowanie do Twojego użytkowania, niniejsza Licencja Publiczna nie ma zastosowania, i nie musisz przestrzegać jej warunków.

3. __Okres.__ Okres obowiązywania niniejszej Licencji Publicznej jest określony w sekcji 6(a).

4. __Nośniki i formaty; dozwolone modyfikacje techniczne.__ Licencjodawca upoważnia Cię do korzystania z Praw Licencjonowanych we wszystkich nośnikach i formatach, zarówno obecnie znanych, jak i stworzonych w przyszłości, oraz do dokonywania niezbędnych modyfikacji technicznych w celu realizacji tego prawa. Licencjodawca zrzeka się i/lub zgadza się nie wywierać żadnego prawa ani władzy, aby zabronić Ci dokonywania modyfikacji technicznych niezbędnych do korzystania z Praw Licencjonowanych, w tym modyfikacji technicznych niezbędnych do obejścia Skutecznych Środków Technicznych. W celu niniejszej Licencji Publicznej, dokonywanie modyfikacji uprawnionych przez niniejszą sekcję 2(a)(4) nigdy nie prowadzi do powstania Materiałów Przystosowanych.

5. __Odbiorcy wtórni.__

A. __Oferta od Licencjodawcy – Materiały Licencjonowane.__ Każdy odbiorca Materiałów Licencjonowanych automatycznie otrzymuje ofertę od Licencjodawcy do korzystania z Praw Licencjonowanych na warunkach określonych w niniejszej Licencji Publicznej.

B. __Brak ograniczeń dla odbiorców wtórnych.__ Nie możesz oferować ani nakładać dodatkowych lub innych warunków na Materiały Licencjonowane ani stosować Skutecznych Środków Technicznych, jeśli uniemożliwia to korzystanie z Praw Licencjonowanych przez jakiegokolwiek odbiorcę Materiałów Licencjonowanych.

6. __Brak poparcia.__ Nic w niniejszej Licencji Publicznej nie stanowi ani nie może być interpretowane jako zgoda na twierdzenie lub sugerowanie, że Ty jesteś, lub że Twoje korzystanie z Materiałów Licencjonowanych jest związane z, lub sponsorowane, poparte lub przyznane oficjalny status przez Licencjodawcę lub inne podmioty uprawnione do otrzymania przypisania, zgodnie z sekcją 3(a)(1)(A)(i).

b. ___Inne prawa.___

1. Prawa moralne, takie jak prawo do integralności, nie są objęte licencją w ramach niniejszej Licencji Publicznej, ani prawa do publicznego wykorzystania wizerunku, prywatności i/lub innych podobnych praw osobistych; jednak, w miarę możliwości, Licencjodawca zrzeka się i/lub zgadza się nie wywierać takich praw przysługujących Licencjodawcy w zakresie koniecznym do umożliwienia Tobie korzystania z Praw Licencjonowanych, ale nie dalej.

2. Prawa patentowe i znaków towarowych nie są objęte licencją w ramach niniejszej Licencji Publicznej.

3. W miarę możliwości, Licencjodawca zrzeka się prawa do pobierania tantiem od Ciebie za korzystanie z Praw Licencjonowanych, bezpośrednio lub za pośrednictwem organizacji zbiorowego zarządzania w ramach dobrowolnego lub obowiązkowego systemu licencjonowania. W pozostałych przypadkach Licencjodawca wyraźnie zastrzega sobie prawo do pobierania takich tantiem, w tym w przypadku korzystania z Materiałów Licencjonowanych w celach innych niż niekomercyjne.

## Sekcja 3 – Warunki Licencji.

Twoje korzystanie z Praw Licencjonowanych jest wyraźnie uzależnione od spełnienia następujących warunków.

a. ___Przypisanie.___

1. Jeśli Udostępniasz Materiały Licencjonowane (w tym w zmienionej formie), musisz:

A. zachować następujące informacje, jeśli są dostarczone przez Licencjodawcę wraz z Materiałami Licencjonowanymi:

i. identyfikację twórców Materiałów Licencjonowanych i innych osób wyznaczonych do otrzymania przypisania, w dowolny rozsądny sposób żądany przez Licencjodawcę (w tym pod pseudonimem, jeśli jest wyznaczony);

ii. oznaczenie praw autorskich;

iii. oznaczenie odnoszące się do niniejszej Licencji Publicznej;

iv. oznaczenie odnoszące się do wyłączenia gwarancji;

v. URI lub hiperłącze do Materiałów Licencjonowanych, w miarę możliwości;

B. wskazać, czy dokonałeś modyfikacji Materiałów Licencjonowanych i zachować wskazanie wcześniejszych modyfikacji; oraz

C. wskazać, że Materiały Licencjonowane są objęte niniejszą Licencją Publiczną i zawrzeć tekst lub URI lub hiperłącze do niniejszej Licencji Publicznej.

2. Możesz spełnić warunki określone w sekcji 3(a)(1) w dowolny rozsądny sposób, zależnie od medium, środków i kontekstu, w którym Udostępniasz Materiały Licencjonowane. Na przykład, może być rozsądne spełnienie warunków poprzez podanie URI lub hiperłącza do zasobu zawierającego wymagane informacje.

3. Jeśli Licencjodawca tego żąda, musisz usunąć wszelkie informacje wymagane przez sekcję 3(a)(1)(A) w miarę możliwości.

4. Jeśli Udostępniasz Materiały Przystosowane, które wyprodukowałeś, Licencja Adaptera, którą stosujesz, nie może uniemożliwiać odbiorcom Materiałów Przystosowanych przestrzegania niniejszej Licencji Publicznej.

## Sekcja 4 – Prawa Bazy Danych Sui Generis.

Jeśli Prawa Licencjonowane obejmują Prawa Bazy Danych Sui Generis, które mają zastosowanie do Twojego korzystania z Materiałów Licencjonowanych:

a. dla uniknięcia wątpliwości, sekcja 2(a)(1) przyznaje Ci prawo do wydobywania, ponownego wykorzystywania, reprodukcji i Udostępniania całej lub znacznej części zawartości bazy danych wyłącznie w celach niekomercyjnych;

b. jeśli zawierasz całą lub znaczną część zawartości bazy danych w bazie danych, w której posiadasz Prawa Bazy Danych Sui Generis, to baza danych, w której posiadasz Prawa Bazy Danych Sui Generis (ale nie jej poszczególne elementy) jest Materiałem Przystosowanym; oraz

c. musisz spełnić warunki określone w sekcji 3(a), jeśli Udostępniasz całą lub znaczną część zawartości bazy danych.

Dla uniknięcia wątpliwości, niniejsza Sekcja 4 uzupełnia i nie zastępuje Twoich obowiązków wynikających z niniejszej Licencji Publicznej, w przypadku gdy Prawa Licencjonowane obejmują inne Prawa Autorskie i Podobne Prawa.

## Sekcja 5 – Wyłączenie
## Sekcja 7 - Inne warunki i postanowienia.

a. Licencjodawca nie będzie związany żadnymi dodatkowymi lub innymi warunkami, które zostały przekazane przez Ciebie, chyba że wyraźnie się na to zgodził.

b. Wszelkie ustalenia, porozumienia lub umowy dotyczące Materiału Licencyjnego, które nie zostały wymienione w niniejszej Licencji Publicznej, są odrębne od warunków tej Licencji Publicznej i niezależne od nich.

## Sekcja 8 - Interpretacja.

a. W celu uniknięcia wątpliwości, niniejsza Licencja Publiczna nie ogranicza, nie ogranicza, nie narzuca warunków ani nie wprowadza ograniczeń dotyczących jakiejkolwiek używki Materiału Licencyjnego, która mogłaby być dokonana bez zgody na mocy niniejszej Licencji Publicznej.

b. W miarę możliwości, jeśli jakiekolwiek postanowienie niniejszej Licencji Publicznej zostanie uznane za niewykonalne, zostanie automatycznie zmienione w minimalnym zakresie koniecznym do jego wykonalności. Jeśli postanowienie nie może zostać zmienione, zostanie ono odłączone od niniejszej Licencji Publicznej, bez wpływu na wykonalność pozostałych warunków.

c. Żadne postanowienie niniejszej Licencji Publicznej nie będzie uważane za zrzeczenie się ani zgoda na niewykonanie, chyba że wyraźnie się na to zgodzono przez Licencjodawcę.

d. Nic w niniejszej Licencji Publicznej nie stanowi ani nie może być interpretowane jako ograniczenie lub zrzeczenie się jakichkolwiek przywilejów i immunitetów, które przysługują Licencjodawcy lub Tobie, w tym przed procesami sądowymi jakiejkolwiek jurysdykcji lub organu władzy.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
