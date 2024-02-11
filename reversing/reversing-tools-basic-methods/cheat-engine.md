<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania, gdzie w pamięci działającej gry są przechowywane ważne wartości i ich zmieniania.\
Po pobraniu i uruchomieniu programu, zostaniesz **poinstruowany** w jaki sposób korzystać z narzędzia. Jeśli chcesz nauczyć się korzystać z narzędzia, zdecydowanie zaleca się ukończenie instrukcji.

# Czego szukasz?

![](<../../.gitbook/assets/image (580).png>)

To narzędzie jest bardzo przydatne do znajdowania, gdzie w pamięci programu jest przechowywana **pewna wartość** (zwykle liczba).\
**Zwykle liczby** są przechowywane w formie **4 bajtów**, ale można je również znaleźć w formatach **double** lub **float**, lub możesz szukać czegoś **innego niż liczba**. Dlatego musisz upewnić się, że **wybierasz** to, czego **szukasz**:

![](<../../.gitbook/assets/image (581).png>)

Możesz również wskazać **różne** rodzaje **wyszukiwań**:

![](<../../.gitbook/assets/image (582).png>)

Możesz również zaznaczyć pole wyboru, aby **zatrzymać grę podczas skanowania pamięci**:

![](<../../.gitbook/assets/image (584).png>)

## Skróty klawiszowe

W _**Edycja --> Ustawienia --> Skróty klawiszowe**_ możesz ustawić różne **skróty klawiszowe** do różnych celów, takich jak **zatrzymywanie** gry (co jest bardzo przydatne, jeśli w pewnym momencie chcesz przeskanować pamięć). Dostępne są inne opcje:

![](<../../.gitbook/assets/image (583).png>)

# Modyfikowanie wartości

Gdy już **znalazłeś** miejsce, gdzie jest **poszukiwana wartość** (więcej na ten temat w kolejnych krokach), możesz ją **zmodyfikować**, klikając dwukrotnie na nią, a następnie dwukrotnie klikając na jej wartość:

![](<../../.gitbook/assets/image (585).png>)

Następnie zaznacz pole wyboru, aby dokonać modyfikacji w pamięci:

![](<../../.gitbook/assets/image (586).png>)

Zmiana w pamięci zostanie natychmiast **zastosowana** (zauważ, że dopóki gra nie użyje tej wartości ponownie, wartość **nie zostanie zaktualizowana w grze**).

# Wyszukiwanie wartości

Załóżmy, że istnieje ważna wartość (np. życie twojego użytkownika), którą chcesz poprawić, i szukasz tej wartości w pamięci.

## Przez znane zmiany

Załóżmy, że szukasz wartości 100, wykonujesz skanowanie w poszukiwaniu tej wartości i znajdujesz wiele zgodności:

![](<../../.gitbook/assets/image (587).png>)

Następnie wykonujesz jakąś czynność, aby **zmienić wartość**, a następnie **zatrzymujesz** grę i wykonujesz **następne skanowanie**:

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine będzie szukał **wartości**, które **zmieniły się z 100 na nową wartość**. Gratulacje, **znalazłeś adres** poszukiwanej wartości, teraz możesz ją zmodyfikować.\
_Jeśli nadal masz kilka wartości, wykonaj jakąś czynność, aby ponownie zmodyfikować tę wartość, a następnie wykonaj kolejne skanowanie, aby przefiltrować adresy._

## Nieznana wartość, znana zmiana

W przypadku, gdy **nie znasz wartości**, ale wiesz, **jak ją zmienić** (nawet wartość zmiany), możesz szukać swojej liczby.

Rozpocznij od wykonania skanu o typie "**Nieznana wartość początkowa**":

![](<../../.gitbook/assets/image (589).png>)

Następnie dokonaj zmiany wartości, wskaż, **jak** wartość **zmieniła się** (w moim przypadku zmniejszyła się o 1) i wykonaj **następne skanowanie**:

![](<../../.gitbook/assets/image (590).png>)

Zostaną wyświetlone **wszystkie wartości, które zostały zmodyfikowane w wybrany sposób**:

![](<../../.gitbook/assets/image (591).png>)

Gdy już znajdziesz swoją wartość, możesz ją zmodyfikować.

Zauważ, że istnieje **wiele możliwych zmian** i możesz wykonywać te **kroki tak wiele razy, jak chcesz**, aby przefiltrować wyniki:

![](<../../.gitbook/assets/image (592).png>)

## Losowy adres pamięci - Znajdowanie kodu

Do tej pory nauczyliśmy się, jak znaleźć adres przechowujący wartość, ale jest bardzo prawdopodobne, że w **różnych wykonaniach gry ten adres znajduje się w różnych miejscach pamięci**. Dowiedzmy się teraz, jak zawsze znaleźć ten adres.

Korzystając z niektórych wspomnianych sztuczek, znajdź adres, w którym twoja obecna gra przechowuje ważną wartość. Następnie (zatrzymując grę, jeśli chcesz) kliknij prawym przyciskiem myszy na znalezionym adresie i wybierz "**Znajdź, co korzysta z tego adresu**" lub "**Znajdź, co zapisuje do tego adresu**":

![](<../../.gitbook/assets/image (593).png>)

**Pierwsza opcja** jest przydatna, aby dowiedzieć się, które **części** kodu **korzystają** z tego **adresu** (co jest przydatne do innych rzeczy, takich jak **znajdowanie miejsca, w którym można zmodyfikować kod** gry).\
**Druga opcja** jest bardziej **konkretna** i będzie bardziej pomocna w tym przypadku, ponieważ interesuje nas, **skąd jest zapisywana ta wartość**.

Po wybraniu jednej z tych opcji, **debugger** zostanie **podłączony** do programu, a pojawi się nowe **puste okno**. Teraz **uruchom** grę i **zmodyfikuj** tę **wartość** (bez ponownego uruchamiania gry). **Okno** powinno być **wypełnione** adresami, które **modyfikują** wartość:

![](<../../.gitbook/assets/image (594).png>)

Teraz, gdy znalazłeś adres, który modyfikuje wartość, możesz **zmodyfikować kod według własnego uznania** (Cheat Engine pozwala na szybkie modyfikowanie go na NOPs):

![](<../../.gitbook/assets/image (595).png>)

Teraz możesz go zmodyfikować, aby kod nie wpływał na twoją liczbę lub zawsze wpływał w pozytywny sposób.
## Losowy adres pamięci - Znajdowanie wskaźnika

Kontynuując poprzednie kroki, znajdź miejsce, w którym znajduje się interesująca cię wartość. Następnie, korzystając z opcji "**Znajdź, co zapisuje do tego adresu**", dowiedz się, który adres zapisuje tę wartość, a następnie kliknij dwukrotnie, aby wyświetlić widok rozkładu:

![](<../../.gitbook/assets/image (596).png>)

Następnie, wykonaj nowe skanowanie, **szukając wartości szesnastkowej między "\[]"** (wartość $edx w tym przypadku):

![](<../../.gitbook/assets/image (597).png>)

(Jeśli pojawi się ich kilka, zazwyczaj potrzebujesz tego o najmniejszym adresie)\
Teraz **znaleźliśmy wskaźnik, który będzie modyfikował interesującą nas wartość**.

Kliknij "**Dodaj adres ręcznie**":

![](<../../.gitbook/assets/image (598).png>)

Następnie, zaznacz pole wyboru "Wskaźnik" i dodaj znaleziony adres w polu tekstowym (w tym scenariuszu znaleziony adres na poprzednim obrazku to "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (599).png>)

(Zauważ, jak pierwszy "Adres" jest automatycznie wypełniany adresem wskaźnika, który wprowadzasz)

Kliknij OK, a zostanie utworzony nowy wskaźnik:

![](<../../.gitbook/assets/image (600).png>)

Teraz, za każdym razem, gdy zmienisz tę wartość, **zmieniasz ważną wartość, nawet jeśli adres pamięci, w którym znajduje się wartość, jest inny**.

## Wstrzykiwanie kodu

Wstrzykiwanie kodu to technika, w której wstrzykujesz fragment kodu do docelowego procesu, a następnie przekierowujesz wykonanie kodu, aby przejść przez twój własny napisany kod (na przykład dawanie ci punktów zamiast odejmowania ich).

Wyobraź sobie, że znalazłeś adres, który odejmuje 1 od życia twojego gracza:

![](<../../.gitbook/assets/image (601).png>)

Kliknij "Pokaż deasembler", aby uzyskać **kod rozkładu**.\
Następnie kliknij **CTRL+a**, aby wywołać okno Auto Assemble, a następnie wybierz _**Szablon --> Wstrzykiwanie kodu**_

![](<../../.gitbook/assets/image (602).png>)

Wypełnij **adres instrukcji, którą chcesz zmodyfikować** (zazwyczaj jest to automatycznie wypełniane):

![](<../../.gitbook/assets/image (603).png>)

Wygenerowany zostanie szablon:

![](<../../.gitbook/assets/image (604).png>)

Wstaw swój nowy kod asemblera w sekcji "**newmem**" i usuń oryginalny kod z sekcji "**originalcode**", jeśli nie chcesz, aby był wykonany. W tym przykładzie wstrzyknięty kod doda 2 punkty zamiast odejmować 1:

![](<../../.gitbook/assets/image (605).png>)

**Kliknij wykonaj i tak dalej, a twój kod powinien zostać wstrzyknięty do programu, zmieniając zachowanie funkcjonalności!**

# **Odnośniki**

* **Samouczek Cheat Engine, ukończ go, aby nauczyć się, jak zacząć korzystać z Cheat Engine**



<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos**.

</details>
