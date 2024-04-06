<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>


## Podstawowe pojęcia

- **Smart Contract** to programy, które wykonują się na blockchainie, gdy spełnione są określone warunki, automatyzując wykonanie umów bez pośredników.
- **Decentralized Applications (dApps)** opierają się na smart contractach i posiadają przyjazny dla użytkownika interfejs front-end oraz transparentne, audytowalne zaplecze back-end.
- **Tokeny i monety** różnią się tym, że monety służą jako cyfrowe pieniądze, podczas gdy tokeny reprezentują wartość lub własność w określonym kontekście.
- **Utility Tokens** umożliwiają dostęp do usług, a **Security Tokens** oznaczają posiadanie aktywów.
- **DeFi** oznacza Decentralized Finance i oferuje usługi finansowe bez centralnych władz.
- **DEX** i **DAO** odnoszą się odpowiednio do platform giełd dezentralizowanych i zdecentralizowanych organizacji autonomicznych.

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczne i uzgodnione weryfikacje transakcji na blockchainie:
- **Proof of Work (PoW)** polega na wykorzystaniu mocy obliczeniowej do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga, aby walidatorzy posiadaliby określoną ilość tokenów, co redukuje zużycie energii w porównaniu do PoW.

## Podstawy Bitcoina

### Transakcje

Transakcje Bitcoin polegają na transferze środków między adresami. Transakcje są weryfikowane za pomocą podpisów cyfrowych, zapewniając, że tylko właściciel klucza prywatnego może inicjować transfery.

#### Kluczowe składniki:

- **Transakcje wielopodpisowe** wymagają wielu podpisów do autoryzacji transakcji.
- Transakcje składają się z **wejść** (źródło środków), **wyjść** (cel), **opłat** (płatne dla górników) i **skryptów** (reguły transakcji).

### Sieć Lightning

Ma na celu zwiększenie skalowalności Bitcoina, umożliwiając wiele transakcji w ramach jednego kanału i tylko transmitowanie ostatecznego stanu do blockchaina.

## Zagrożenia prywatności Bitcoina

Ataki na prywatność, takie jak **Wspólne posiadanie wejść** i **Wykrywanie adresów zmiany UTXO**, wykorzystują wzorce transakcji. Strategie takie jak **Mieszalniki** i **CoinJoin** poprawiają anonimowość, utrudniając śledzenie powiązań transakcji między użytkownikami.

## Anonimowe pozyskiwanie Bitcoinów

Metody obejmują handel gotówkowy, kopanie i korzystanie z mieszalników. **CoinJoin** miesza wiele transakcji, aby utrudnić śledzenie, podczas gdy **PayJoin** maskuje CoinJoiny jako zwykłe transakcje dla zwiększonej prywatności.


# Ataki na prywatność Bitcoina

# Podsumowanie ataków na prywatność Bitcoina

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników często budzą obawy. Oto uproszczony przegląd kilku powszechnych metod, za pomocą których atakujący mogą naruszyć prywatność Bitcoina.

## **Założenie o wspólnym posiadaniu wejść**

Zazwyczaj jest rzadkością, aby wejścia od różnych użytkowników były łączone w jednej transakcji ze względu na złożoność. Dlatego **dwa adresy wejściowe w tej samej transakcji często są uważane za należące do tego samego właściciela**.

## **Wykrywanie adresów zmiany UTXO**

UTXO, czyli **Unspent Transaction Output**, musi być w całości wydane w transakcji. Jeśli tylko część z niego zostanie wysłana na inny adres, reszta trafia na nowy adres zmiany. Obserwatorzy mogą przypuszczać, że ten nowy adres należy do nadawcy, naruszając prywatność.

### Przykład
Aby złagodzić ten problem, usługi mieszające lub korzystanie z wielu adresów mogą pomóc ukryć właściciela.

## **Wystawienie na sieciach społecznościowych i forach**

Użytkownicy czasami udostępniają swoje adresy Bitcoin online, co czyni **łatwym powiązanie adresu z jego właścicielem**.

## **Analiza grafu transakcji**

Transakcje można przedstawić w postaci grafów, ujawniając potencjalne połączenia między użytkownikami na podstawie przepływu środków.

## **Heurystyka niepotrzebnego wejścia (optymalna heurystyka zmiany)**

Ta heurystyka opiera się na analizie transakcji z wieloma wejściami i wyjściami, aby zgadywać, które wyjście jest zmianą, która wraca do nadawcy.

### Przykład
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Jeśli dodanie większej ilości wejść powoduje, że wyjście jest większe niż pojedyncze wejście, może to wprowadzić zamieszanie w heurystyce.

## **Wymuszane ponowne użycie adresu**

Atakujący mogą wysyłać małe kwoty na wcześniej używane adresy, mając nadzieję, że odbiorca połączy je z innymi wejściami w przyszłych transakcjach, co spowoduje powiązanie adresów.

### Poprawne zachowanie portfela
Portfele powinny unikać używania monet otrzymanych na już używanych, pustych adresach, aby zapobiec wyciekom prywatności.

## **Inne techniki analizy blockchain**

- **Dokładne kwoty płatności:** Transakcje bez reszty są prawdopodobnie między dwoma adresami należącymi do tego samego użytkownika.
- **Kwoty zaokrąglone:** Zaokrąglona kwota w transakcji sugeruje, że jest to płatność, a niezaokrąglone wyjście prawdopodobnie jest resztą.
- **Fingerprinting portfela:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować użyte oprogramowanie i potencjalnie adres reszty.
- **Korelacje kwot i czasu:** Ujawnienie czasu lub kwoty transakcji może ułatwić śledzenie transakcji.

## **Analiza ruchu**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkownika. Dotyczy to zwłaszcza, jeśli podmiot obsługuje wiele węzłów Bitcoin, co zwiększa jego zdolność do monitorowania transakcji.

## Więcej
Aby uzyskać kompletną listę ataków i obrony prywatności, odwiedź [Bitcoin Privacy na Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Anonimowe transakcje Bitcoin

## Sposoby anonimowego zdobywania Bitcoinów

- **Transakcje gotówkowe**: Zdobycie bitcoinów za pomocą gotówki.
- **Alternatywy dla gotówki**: Zakup kart podarunkowych i wymiana ich online na bitcoiny.
- **Kopanie**: Najbardziej prywatnym sposobem na zdobycie bitcoinów jest kopanie, zwłaszcza gdy jest wykonywane samodzielnie, ponieważ puli kopiących może być znany adres IP kopacza. [Informacje o pulach kopiących](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież**: Teoretycznie kradzież bitcoinów może być innym sposobem na anonimowe ich zdobycie, chociaż jest to nielegalne i niezalecane.

## Usługi mieszające

Korzystając z usługi mieszającej, użytkownik może **wysłać bitcoiny** i otrzymać **inne bitcoiny w zamian**, co utrudnia śledzenie pierwotnego właściciela. Jednak wymaga to zaufania do usługi, że nie przechowuje logów i rzeczywiście zwraca bitcoiny. Alternatywne opcje mieszania obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji różnych użytkowników w jedną, utrudniając proces dopasowania wejść do wyjść dla osób próbujących to zrobić. Pomimo swojej skuteczności, transakcje o unikalnych rozmiarach wejść i wyjść wciąż mogą być potencjalnie śledzone.

Przykładowe transakcje, które mogły używać CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Aby uzyskać więcej informacji, odwiedź [CoinJoin](https://coinjoin.io/en). Dla podobnej usługi na Ethereum, sprawdź [Tornado Cash](https://tornado.cash), która anonimizuje transakcje za pomocą środków od kopaczy.

## PayJoin

Wariant CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznego równego rozkładu wyjść, charakterystycznego dla CoinJoin. Utrudnia to wykrycie i może unieważnić heurystykę wspólnego posiadania wejść, używaną przez podmioty monitorujące transakcje.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje takie jak powyższa mogą być PayJoin, zwiększając prywatność, jednocześnie pozostając nierozróżnialne od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin może znacznie zakłócić tradycyjne metody monitorowania**, co czyni go obiecującym rozwiązaniem w dążeniu do prywatności transakcyjnej.


# Najlepsze praktyki dotyczące prywatności w kryptowalutach

## **Techniki synchronizacji portfeli**

Aby zachować prywatność i bezpieczeństwo, synchronizacja portfeli z blockchainem jest kluczowa. Wyróżniają się dwie metody:

- **Pełny węzeł**: Pobierając cały blockchain, pełny węzeł zapewnia maksymalną prywatność. Wszystkie kiedykolwiek wykonane transakcje są przechowywane lokalnie, co uniemożliwia przeciwnikom zidentyfikowanie, które transakcje lub adresy interesują użytkownika.
- **Filtrowanie bloków po stronie klienta**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, pozwalając portfelom identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry, pobierając pełne bloki tylko wtedy, gdy zostanie znalezione dopasowanie z adresami użytkownika.

## **Wykorzystanie Tor do anonimowości**

Biorąc pod uwagę, że Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tor, aby ukryć adres IP, zwiększając prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu użyciu adresów**

Aby chronić prywatność, ważne jest używanie nowego adresu dla każdej transakcji. Ponowne użycie adresów może naruszyć prywatność, łącząc transakcje z tą samą jednostką. Nowoczesne portfele zniechęcają do ponownego użycia adresów poprzez swoje projektowanie.

## **Strategie dla prywatności transakcji**

- **Wiele transakcji**: Podział płatności na kilka transakcji może zaciemnić kwotę transakcji, utrudniając ataki na prywatność.
- **Unikanie reszty**: Wybieranie transakcji, które nie wymagają reszty, zwiększa prywatność poprzez zakłócenie metod wykrywania reszty.
- **Wiele reszt**: Jeśli unikanie reszty nie jest możliwe, generowanie wielu reszt może wciąż poprawić prywatność.

# **Monero: Symbol Anonimowości**

Monero odpowiada na potrzebę absolutnej anonimowości w transakcjach cyfrowych, ustanawiając wysoki standard prywatności.

# **Ethereum: Gas i Transakcje**

## **Zrozumienie Gas**

Gas mierzy wysiłek obliczeniowy potrzebny do wykonania operacji na Ethereum i jest wyceniany w **gwei**. Na przykład transakcja kosztująca 2 310 000 gwei (lub 0,00231 ETH) obejmuje limit gazu, opłatę podstawową oraz napiwek dla zachęcenia górników. Użytkownicy mogą ustawić maksymalną opłatę, aby upewnić się, że nie przepłacają, a nadwyżka zostaje zwrócona.

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którzy mogą być adresami użytkownika lub inteligentnymi kontraktami. Wymagają one opłaty i muszą być wydobywane. Istotne informacje w transakcji obejmują odbiorcę, podpis nadawcy, wartość, opcjonalne dane, limit gazu i opłaty. Należy zauważyć, że adres nadawcy jest wydedukowany z podpisu, eliminując potrzebę jego umieszczania w danych transakcji.

Te praktyki i mechanizmy są podstawą dla każdego, kto chce korzystać z kryptowalut, priorytetowo traktując prywatność i bezpieczeństwo.


## Referencje

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos.**

</details>
