# Cheat Engine

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania, gdzie ważne wartości są zapisywane w pamięci działającej gry i zmiany tych wartości.\
Po pobraniu i uruchomieniu programu, **otrzymasz** samouczek, jak korzystać z narzędzia. Jeśli chcesz nauczyć się korzystać z narzędzia, zaleca się ukończenie samouczka.

## Czego szukasz?

![](<../../.gitbook/assets/image (762).png>)

To narzędzie jest bardzo przydatne do znalezienia, **gdzie pewna wartość** (zwykle liczba) **jest przechowywana w pamięci** programu.\
**Zazwyczaj liczby** są przechowywane w formie **4 bajtów**, ale można je również znaleźć w formatach **double** lub **float**, lub możesz chcieć szukać czegoś **innego niż liczba**. Dlatego musisz upewnić się, że **wybierasz**, czego chcesz **szukać**:

![](<../../.gitbook/assets/image (324).png>)

Możesz również wskazać **różne** rodzaje **wyszukiwań**:

![](<../../.gitbook/assets/image (311).png>)

Możesz również zaznaczyć pole, aby **zatrzymać grę podczas skanowania pamięci**:

![](<../../.gitbook/assets/image (1052).png>)

### Skróty klawiszowe

W _**Edycja --> Ustawienia --> Skróty klawiszowe**_ możesz ustawić różne **skróty klawiszowe** do różnych celów, takich jak **zatrzymywanie** **gry** (co jest bardzo przydatne, jeśli chcesz skanować pamięć w pewnym momencie). Dostępne są inne opcje:

![](<../../.gitbook/assets/image (864).png>)

## Modyfikowanie wartości

Gdy już **znajdziesz**, gdzie jest **wartość**, której **szukasz** (więcej na ten temat w kolejnych krokach), możesz ją **zmodyfikować**, dwukrotnie klikając na nią, a następnie dwukrotnie klikając na jej wartość:

![](<../../.gitbook/assets/image (563).png>)

I wreszcie zaznacz pole wyboru, aby dokonać modyfikacji w pamięci:

![](<../../.gitbook/assets/image (385).png>)

Zmiana w **pamięci** zostanie natychmiast **zastosowana** (zauważ, że dopóki gra nie użyje tej wartości ponownie, wartość **nie zostanie zaktualizowana w grze**).

## Wyszukiwanie wartości

Załóżmy, że istnieje ważna wartość (np. życie twojego użytkownika), którą chcesz poprawić, i szukasz tej wartości w pamięci)

### Poprzez znane zmiany

Załóżmy, że szukasz wartości 100, **wykonujesz skan**, szukając tej wartości i znajdujesz wiele zbieżności:

![](<../../.gitbook/assets/image (108).png>)

Następnie zrób coś, aby **wartość się zmieniła**, zatrzymaj grę i **wykonaj** **następne skanowanie**:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine będzie szukał **wartości**, które **zmieniły się z 100 na nową wartość**. Gratulacje, **znalazłeś adres** wartości, której szukałeś, teraz możesz ją zmodyfikować.\
_Jeśli nadal masz kilka wartości, zrób coś, aby ponownie zmodyfikować tę wartość i wykonaj kolejne "następne skanowanie", aby przefiltrować adresy._

### Nieznana wartość, znana zmiana

W scenariuszu, gdy **nie znasz wartości**, ale wiesz, **jak ją zmienić** (nawet wartość zmiany), możesz szukać swojej liczby.

Zacznij od wykonania skanu typu "**Nieznana wartość początkowa**":

![](<../../.gitbook/assets/image (890).png>)

Następnie zmień wartość, wskazując, **jak** **wartość** **zmieniła się** (w moim przypadku została zmniejszona o 1) i wykonaj **następne skanowanie**:

![](<../../.gitbook/assets/image (371).png>)

Zostaną przedstawione **wszystkie wartości, które zostały zmodyfikowane w wybrany sposób**:

![](<../../.gitbook/assets/image (569).png>)

Gdy już znajdziesz swoją wartość, możesz ją zmodyfikować.

Zauważ, że istnieje **wiele możliwych zmian** i możesz wykonywać te **kroki tak często, jak chcesz**, aby przefiltrować wyniki:

![](<../../.gitbook/assets/image (574).png>)

### Losowy adres pamięci - Znajdowanie kodu

Do tej pory nauczyliśmy się, jak znaleźć adres przechowujący wartość, ale jest bardzo prawdopodobne, że w **różnych wykonaniach gry ten adres znajduje się w różnych miejscach pamięci**. Dowiedzmy się teraz, jak zawsze znaleźć ten adres.

Korzystając z jednej z wymienionych sztuczek, znajdź adres, w którym twoja obecna gra przechowuje ważną wartość. Następnie (zatrzymując grę, jeśli chcesz) kliknij prawym przyciskiem myszy na znalezionym **adresie** i wybierz "**Znajdź, co ma dostęp do tego adresu**" lub "**Znajdź, co zapisuje do tego adresu**":

![](<../../.gitbook/assets/image (1067).png>)

**Pierwsza opcja** jest przydatna do poznania, które **części** **kodu** korzystają z tego **adresu** (co jest przydatne do innych rzeczy, takich jak **znajomość, gdzie można zmodyfikować kod** gry).\
**Druga opcja** jest bardziej **specyficzna** i będzie bardziej pomocna w tym przypadku, ponieważ interesuje nas, **skąd jest zapisywana ta wartość**.

Po wybraniu jednej z tych opcji, **debugger** zostanie **dołączony** do programu, a pojawi się nowe **puste okno**. Teraz **zagraj** w **grę** i **zmodyfikuj** tę **wartość** (bez ponownego uruchamiania gry). **Okno** powinno być **wypełnione** adresami, które **modyfikują** wartość:

![](<../../.gitbook/assets/image (91).png>)

Teraz, gdy już znalazłeś adres, który modyfikuje wartość, możesz **zmodyfikować kod według własnego uznania** (Cheat Engine pozwala na szybką zmianę na NOPs):

![](<../../.gitbook/assets/image (1057).png>)

Teraz możesz go zmodyfikować, aby kod nie wpływał na twoją liczbę, lub zawsze wpływał w pozytywny sposób.
### Losowy adres pamięci - Znalezienie wskaźnika

Kontynuując poprzednie kroki, znajdź miejsce, w którym znajduje się wartość, która Cię interesuje. Następnie, korzystając z opcji "**Znajdź, co zapisuje do tego adresu**", dowiedz się, który adres zapisuje tę wartość i dwukrotnie kliknij na niego, aby uzyskać widok rozkładu:

![](<../../.gitbook/assets/image (1039).png>)

Następnie wykonaj nowe skanowanie, **szukając wartości szesnastkowej pomiędzy "\[]"** (wartość $edx w tym przypadku):

![](<../../.gitbook/assets/image (994).png>)

(_Jeśli pojawi się kilka wyników, zazwyczaj potrzebujesz tego z najmniejszym adresem_)\
Teraz mamy **znaleziony wskaźnik, który będzie modyfikował wartość, która nas interesuje**.

Kliknij na "**Dodaj adres ręcznie**":

![](<../../.gitbook/assets/image (990).png>)

Następnie zaznacz pole wyboru "Wskaźnik" i dodaj znaleziony adres w polu tekstowym (w tym scenariuszu, znaleziony adres na poprzednim obrazie to "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (392).png>)

(Zauważ, że pierwszy "Adres" jest automatycznie wypełniany z adresu wskaźnika, który wprowadzasz)

Kliknij OK, a zostanie utworzony nowy wskaźnik:

![](<../../.gitbook/assets/image (308).png>)

Teraz za każdym razem, gdy zmieniasz tę wartość, **zmieniasz ważną wartość nawet jeśli adres pamięci, w którym znajduje się wartość, jest inny.**

### Wstrzykiwanie kodu

Wstrzykiwanie kodu to technika, w której wstrzykujesz fragment kodu do procesu docelowego, a następnie przekierowujesz wykonanie kodu, aby przechodziło przez Twój własny napisany kod (np. dając Ci punkty zamiast odejmować je).

Więc, wyobraź sobie, że znalazłeś adres, który odejmuje 1 od życia Twojego gracza:

![](<../../.gitbook/assets/image (203).png>)

Kliknij Pokaż rozkład, aby uzyskać **rozłożony kod**.\
Następnie kliknij **CTRL+a**, aby wywołać okno Auto assemble i wybierz _**Szablon --> Wstrzykiwanie kodu**_

![](<../../.gitbook/assets/image (902).png>)

Wypełnij **adres instrukcji, którą chcesz zmodyfikować** (zazwyczaj jest to automatycznie wypełnione):

![](<../../.gitbook/assets/image (744).png>)

Szablon zostanie wygenerowany:

![](<../../.gitbook/assets/image (944).png>)

Wstaw swój nowy kod montażowy w sekcji "**newmem**" i usuń oryginalny kod z sekcji "**originalcode**", jeśli nie chcesz, aby był on wykonywany. W tym przykładzie wstrzyknięty kod doda 2 punkty zamiast odejmować 1:

![](<../../.gitbook/assets/image (521).png>)

**Kliknij wykonaj i tak dalej, a Twój kod powinien zostać wstrzyknięty do programu, zmieniając zachowanie funkcjonalności!**

## **Referencje**

* **Samouczek Cheat Engine, ukończ go, aby nauczyć się, jak zacząć korzystać z Cheat Engine**
