# Sub-GHz RF

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Drzwi garażowe

Otwieracze drzwi garażowych zazwyczaj działają w zakresie częstotliwości 300-190 MHz, przy czym najczęściej używane są częstotliwości 300 MHz, 310 MHz, 315 MHz i 390 MHz. Ten zakres częstotliwości jest powszechnie stosowany do otwieraczy drzwi garażowych, ponieważ jest mniej zatłoczony niż inne pasma częstotliwości i mniej podatny na zakłócenia ze strony innych urządzeń.

## Drzwi samochodowe

Większość pilotów do samochodów działa na częstotliwości **315 MHz lub 433 MHz**. Są to częstotliwości radiowe, które są używane w różnych aplikacjach. Główną różnicą między tymi dwiema częstotliwościami jest to, że 433 MHz ma większy zasięg niż 315 MHz. Oznacza to, że 433 MHz jest lepsze do zastosowań, które wymagają większego zasięgu, takich jak zdalne otwieranie zamków.\
W Europie powszechnie używana jest częstotliwość 433,92 MHz, a w USA i Japonii jest to 315 MHz.

## **Atak brute-force**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

Jeśli zamiast wysyłać każdy kod 5 razy (wysyłane w ten sposób, aby upewnić się, że odbiornik go otrzymuje), wysyłasz go tylko raz, czas zostaje skrócony do 6 minut:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

a jeśli **usuniesz 2-milisekundowe oczekiwanie** między sygnałami, czas można skrócić do 3 minut.

Ponadto, korzystając z sekwencji De Bruijna (sposobu zmniejszenia liczby bitów potrzebnych do wysłania wszystkich potencjalnych liczb binarnych do przeprowadzenia ataku brute-force), ten **czas zostaje skrócony do zaledwie 8 sekund**:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Przykład tego ataku został zaimplementowany w [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Wymaganie **preambuły zapobiegnie optymalizacji sekwencją De Bruijna**, a **kody zmiennoprzecinkowe uniemożliwią ten atak** (przy założeniu, że kod jest wystarczająco długi, aby nie można go było złamać metodą brute-force).

## Atak na Sub-GHz

Aby zaatakować te sygnały za pomocą Flipper Zero, sprawdź:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Ochrona przed kodami zmiennoprzecinkowymi

Automatyczne otwieracze drzwi garażowych zazwyczaj używają bezprzewodowego pilota do otwierania i zamykania drzwi garażowych. Pilot **wysyła sygnał radiowy (RF)** do otwieracza drzwi garażowych, który uruchamia silnik do otwierania lub zamykania drzwi.

Istnieje możliwość, że ktoś może użyć urządzenia znanego jako grabber kodu, aby przechwycić sygnał RF i zarejestrować go do późniejszego użycia. Jest to znane jako **atak powtórnego odtwarzania**. Aby zapobiec tego rodzaju atakowi, wiele nowoczesnych otwieraczy drzwi garażowych używa bardziej bezpiecznej metody szyfrowania, znanej jako **kod zmiennoprzecinkowy**.

**Sygnał RF jest zazwyczaj przesyłany za pomocą kodu zmiennoprzecinkowego**, co oznacza, że kod zmienia się przy każdym użyciu. Sprawia to, że jest **trudne** dla kogoś, aby **przechwycić** sygnał i **użyć** go do **nieautoryzowanego** dostępu do garażu.

W systemie kodu zmiennoprzecinkowego pilot i otwieracz drzwi garażowych mają **wspólny algorytm**, który **generuje nowy kod** za każdym razem, gdy pilot jest używany. Otwieracz drzwi garażowych odpowie tylko na **poprawny kod**, co znacznie utrudnia nieautoryzowany dostęp do garażu poprzez przechwycenie kodu.

### **Atak na brakujące połączenie**

W zasadzie, nasłuchujesz przycisku i **przechwytujesz sygnał, gdy pilot jest poza zasięgiem** urządzenia (np. samochodu lub garażu). Następnie przechodzisz do urządzenia i **używasz przechwyconego kodu, aby je otworzyć**.

### Pełny atak na zakłócanie połączenia

Atakujący może **zakłócić sygnał w pobliżu pojazdu lub odbiornika**, aby **odbiornik nie mógł "usłyszeć" kodu**, a gdy to się dzieje, można po prostu **przechwycić i odtworzyć** kod, gdy przestaniesz zakłócać.

Ofiara w pewnym momencie użyje **kluczy do zamknięcia samochodu**, ale atak będzie **rejestrował wystarczającą ilość kodów "zamknij drzwi"**, które być może można ponownie wysłać, aby otworzyć drzwi (może być konieczna **zmiana częstotliwości**, ponieważ są samochody, które używają tych samych kodów do otwierania i zamykania, ale nasłuchują obu poleceń na różnych częstotliwościach).

{% hint style="warning" %}
**Zakłócanie działa**, ale jest zauważalne, ponieważ jeśli **osoba zamykająca samochód po prostu sprawdzi drzwi**, aby upewnić się, że są zamknięte, zauważy, że samochód jest otwarty. Dodatkowo, jeśli byliby świadomi takich ataków, mogliby nawet usłyszeć, że drzwi nigdy nie wydały dźwięku **blokady** ani nie zaświeciły się **
### Atak zakłócania sygnału alarmowego

Testowanie systemu aftermarketowego kodu zmieniającego zainstalowanego w samochodzie, **wysyłając ten sam kod dwukrotnie**, natychmiast **aktywowało alarm** i immobilizer, co dawało unikalną możliwość **odmowy usługi**. Ironicznie, aby **wyłączyć alarm** i immobilizer, należało **nacisnąć** **pilot zdalnego sterowania**, co dawało atakującemu możliwość **ciągłego przeprowadzania ataku DoS**. Można również połączyć ten atak z **poprzednim, aby uzyskać więcej kodów**, ponieważ ofiara chciałaby jak najszybciej zatrzymać atak.

## Referencje

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
