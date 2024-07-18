{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}


## Podstawowe Pojęcia

- **Smart Contracts** są programami, które wykonują się na blockchainie po spełnieniu określonych warunków, automatyzując wykonanie umów bez pośredników.
- **Zdecentralizowane Aplikacje (dApps)** opierają się na smart contractach, posiadając przyjazny interfejs użytkownika oraz transparentne, audytowalne zaplecze.
- **Tokeny i Monety** różnią się tym, że monety pełnią funkcję pieniądza cyfrowego, podczas gdy tokeny reprezentują wartość lub własność w określonych kontekstach.
- **Tokeny Użytkowe** umożliwiają dostęp do usług, a **Tokeny Bezpieczeństwa** oznaczają posiadanie aktywów.
- **DeFi** oznacza Zdecentralizowaną Finansówkę, oferującą usługi finansowe bez centralnych władz.
- **DEX** i **DAOs** odnoszą się odpowiednio do Zdecentralizowanych Platform Giełdowych i Zdecentralizowanych Autonomicznych Organizacji.

## Mechanizmy Konsensusu

Mechanizmy konsensusu zapewniają bezpieczne i uzgodnione walidacje transakcji na blockchainie:
- **Proof of Work (PoW)** polega na mocy obliczeniowej do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga, aby walidatorzy posiadalii określoną ilość tokenów, zmniejszając zużycie energii w porównaniu do PoW.

## Podstawy Bitcoina

### Transakcje

Transakcje Bitcoina polegają na przesyłaniu środków między adresami. Transakcje są walidowane poprzez podpisy cyfrowe, zapewniając, że tylko właściciel klucza prywatnego może inicjować transfery.

#### Kluczowe Składniki:

- **Transakcje Multisygnaturowe** wymagają wielu podpisów do autoryzacji transakcji.
- Transakcje składają się z **wejść** (źródła środków), **wyjść** (celu), **opłat** (płaconych górnikom) i **skryptów** (reguł transakcji).

### Sieć Błyskawiczna

Ma na celu zwiększenie skalowalności Bitcoina, pozwalając na wiele transakcji w ramach kanału, a następnie nadając tylko ostateczny stan na blockchainie.

## Problemy Prywatności Bitcoina

Ataki na prywatność, takie jak **Wspólne Posiadanie Wejścia** i **Wykrywanie Adresu Zmiany UTXO**, wykorzystują wzorce transakcji. Strategie takie jak **Miksery** i **CoinJoin** poprawiają anonimowość, zacieniając powiązania transakcyjne między użytkownikami.

## Nabywanie Bitcoinów Anonimowo

Metody obejmują handel gotówką, kopanie oraz korzystanie z miksów. **CoinJoin** miesza wiele transakcji, komplikując śledzenie, podczas gdy **PayJoin** maskuje CoinJoiny jako zwykłe transakcje dla zwiększonej prywatności.


# Ataki na Prywatność Bitcoina

# Podsumowanie Ataków na Prywatność Bitcoina

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników często budzą zaniepokojenie. Oto uproszczony przegląd kilku powszechnych metod, za pomocą których atakujący mogą naruszyć prywatność Bitcoina.

## **Założenie Wspólnego Posiadania Wejścia**

Zazwyczaj rzadko zdarza się, że wejścia od różnych użytkowników są łączone w jednej transakcji ze względu na złożoność. Dlatego **dwa adresy wejściowe w tej samej transakcji są często uważane za należące do tego samego właściciela**.

## **Wykrywanie Adresu Zmiany UTXO**

UTXO, czyli **Niewykorzystany Wynik Transakcji**, musi być całkowicie wydany w transakcji. Jeśli tylko część z niego jest wysyłana na inny adres, reszta trafia na nowy adres zmiany. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, naruszając prywatność.

### Przykład
```bash
2 btc --> 4 btc
3 btc     1 btc
```
## **Wymuszane Ponowne Użycie Adresu**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, mając nadzieję, że odbiorca połączy je z innymi wejściami w przyszłych transakcjach, co spowoduje powiązanie adresów.

### Poprawne Zachowanie Portfela
Portfele powinny unikać używania monet otrzymanych na już używanych, pustych adresach, aby zapobiec wyciekowi prywatności.

## **Inne Techniki Analizy Blockchain**

- **Dokładne Kwoty Płatności:** Transakcje bez reszty prawdopodobnie odbywają się między dwoma adresami należącymi do tego samego użytkownika.
- **Kwoty Zaokrąglone:** Kwota zaokrąglona w transakcji sugeruje, że jest to płatność, a niezaokrąglony wynik prawdopodobnie jest resztą.
- **Identyfikacja Portfela:** Różne portfele mają unikalne wzorce tworzenia transakcji, pozwalając analitykom zidentyfikować użyte oprogramowanie i potencjalnie adres reszty.
- **Korelacje Kwot i Czasu:** Ujawnienie czasów lub kwot transakcji może sprawić, że transakcje staną się śledzalne.

## **Analiza Ruchu**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Szczególnie dotyczy to sytuacji, gdy podmiot obsługuje wiele węzłów Bitcoin, zwiększając zdolność monitorowania transakcji.

## Więcej
Aby uzyskać kompletną listę ataków na prywatność i obrony przed nimi, odwiedź [Bitcoin Privacy na Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Anonimowe Transakcje Bitcoin

## Sposoby na Uzyskanie Bitcoinów Anonimowo

- **Transakcje Gotówkowe**: Pozyskiwanie bitcoinów za gotówkę.
- **Alternatywy Gotówkowe**: Zakup kart podarunkowych i wymiana ich online na bitcoiny.
- **Kopanie**: Najbardziej prywatny sposób zdobycia bitcoinów to kopanie, zwłaszcza gdy jest wykonywane samodzielnie, ponieważ pule górnicze mogą znać adres IP górnika. [Informacje o Pulach Górniczych](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież**: Teoretycznie kradzież bitcoinów mógłby być kolejnym sposobem na ich anonimowe pozyskanie, chociaż jest to nielegalne i niezalecane.

## Usługi Mieszania

Korzystając z usługi mieszania, użytkownik może **wysłać bitcoiny** i otrzymać **inne bitcoiny w zamian**, co utrudnia śledzenie pierwotnego właściciela. Wymaga to jednak zaufania do usługi, aby nie przechowywała logów i faktycznie zwróciła bitcoiny. Alternatywne opcje mieszania obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji od różnych użytkowników w jedną, komplikując proces dla osób próbujących dopasować wejścia do wyjść. Pomimo swojej skuteczności, transakcje z unikalnymi rozmiarami wejść i wyjść wciąż mogą potencjalnie być śledzone.

Przykładowe transakcje, które mogły zostać wykonane za pomocą CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Aby uzyskać więcej informacji, odwiedź [CoinJoin](https://coinjoin.io/en). Dla podobnej usługi na Ethereum, sprawdź [Tornado Cash](https://tornado.cash), która anonimizuje transakcje za pomocą środków od górników.

## PayJoin

Wariant CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję między dwiema stronami (np. klientem i handlowcem) jako zwykłą transakcję, bez charakterystycznych równych wyjść charakterystycznych dla CoinJoin. Sprawia to, że jest bardzo trudne do wykrycia i może unieważnić heurystykę wspólnego właściciela wejścia, używaną przez podmioty monitorujące transakcje.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje jak powyższa mogą być PayJoin, zwiększając prywatność, pozostając jednocześnie nie do odróżnienia od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin może znacząco zakłócić tradycyjne metody nadzoru**, co czyni go obiecującym rozwojem w dążeniu do prywatności transakcyjnej.


# Najlepsze praktyki dotyczące prywatności w kryptowalutach

## **Techniki synchronizacji portfela**

Aby zachować prywatność i bezpieczeństwo, synchronizacja portfeli z blockchainem jest kluczowa. Wyróżniają się dwie metody:

- **Pełny węzeł**: Pobierając cały blockchain, pełny węzeł zapewnia maksymalną prywatność. Wszystkie dokonane transakcje są przechowywane lokalnie, co uniemożliwia przeciwnikom zidentyfikowanie, które transakcje lub adresy użytkownika ich interesują.
- **Filtrowanie bloków po stronie klienta**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, pozwalając portfelom identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry, pobierając pełne bloki tylko wtedy, gdy zostanie znalezione dopasowanie z adresami użytkownika.

## **Wykorzystanie Tor dla Anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tor, aby zasłonić swój adres IP, zwiększając prywatność podczas interakcji z siecią.

## **Zapobieganie Ponownemu Używaniu Adresów**

Aby chronić prywatność, ważne jest używanie nowego adresu dla każdej transakcji. Ponowne używanie adresów może naruszyć prywatność, łącząc transakcje z tą samą jednostką. Nowoczesne portfele zniechęcają do ponownego używania adresów poprzez swoje projekty.

## **Strategie dla Prywatności Transakcji**

- **Wiele transakcji**: Podzielenie płatności na kilka transakcji może zaciemnić kwotę transakcji, udaremniając ataki na prywatność.
- **Unikanie reszty**: Wybieranie transakcji, które nie wymagają reszty, zwiększa prywatność poprzez zakłócenie metod wykrywania reszty.
- **Wiele reszt**: Jeśli unikanie reszty nie jest możliwe, generowanie wielu reszt nadal może poprawić prywatność.

# **Monero: Latarnia Anonimowości**

Monero odpowiada na potrzebę absolutnej anonimowości w transakcjach cyfrowych, ustanawiając wysoki standard prywatności.

# **Ethereum: Gas i Transakcje**

## **Rozumienie Gazu**

Gas mierzy wysiłek obliczeniowy potrzebny do wykonania operacji na Ethereum, wyceniany w **gwei**. Na przykład transakcja kosztująca 2 310 000 gwei (lub 0,00231 ETH) obejmuje limit gazu, opłatę podstawową oraz napiwek dla zachęty dla górników. Użytkownicy mogą ustawić maksymalną opłatę, aby upewnić się, że nie przepłacają, a nadwyżka zostanie zwrócona.

## **Wykonywanie Transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którzy mogą być adresami użytkownika lub inteligentnych kontraktów. Wymagają one opłaty i muszą być wydobywane. Istotne informacje w transakcji obejmują odbiorcę, podpis nadawcy, wartość, opcjonalne dane, limit gazu i opłaty. Warto zauważyć, że adres nadawcy jest wydedukowany z podpisu, eliminując potrzebę jego zawarcia w danych transakcji.

Te praktyki i mechanizmy stanowią fundament dla każdego, kto chce zaangażować się w kryptowaluty, priorytetyzując prywatność i bezpieczeństwo.


## Referencje

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępnij sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
