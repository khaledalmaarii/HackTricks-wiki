# Sub-GHz RF

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Drzwi Garażowe

Otwieracze do bram garażowych zazwyczaj działają w zakresie częstotliwości od 300 do 190 MHz, przy najczęstszych częstotliwościach wynoszących 300 MHz, 310 MHz, 315 MHz i 390 MHz. Ten zakres częstotliwości jest powszechnie używany do otwieraczy do bram garażowych, ponieważ jest mniej zatłoczony niż inne pasma częstotliwości i mniej podatny na zakłócenia ze strony innych urządzeń.

## Drzwi Samochodowe

Większość pilotów do samochodów działa na częstotliwości **315 MHz lub 433 MHz**. Są to częstotliwości radiowe, które są używane w różnych aplikacjach. Główną różnicą między tymi dwiema częstotliwościami jest to, że 433 MHz ma większy zasięg niż 315 MHz. Oznacza to, że 433 MHz jest lepszy do zastosowań wymagających większego zasięgu, takich jak zdalne otwieranie zamków.\
W Europie powszechnie używane jest 433,92 MHz, a w USA i Japonii 315 MHz.

## **Atak Brute-force**

<figure><img src="../../.gitbook/assets/image (1081).png" alt=""><figcaption></figcaption></figure>

Jeśli zamiast wysyłać każdy kod 5 razy (wysyłany w ten sposób, aby odbiornik go odebrał), wysyłasz go tylko raz, czas zostaje skrócony do 6 minut:

<figure><img src="../../.gitbook/assets/image (616).png" alt=""><figcaption></figcaption></figure>

a jeśli **usuniesz 2 ms oczekiwania** między sygnałami, czas można **skrócić do 3 minut**.

Co więcej, korzystając z ciągu De Bruijna (sposób na zmniejszenie liczby bitów potrzebnych do wysłania wszystkich potencjalnych liczb binarnych do ataku brute-force), ten **czas zostaje skrócony do zaledwie 8 sekund**:

<figure><img src="../../.gitbook/assets/image (580).png" alt=""><figcaption></figcaption></figure>

Przykład tego ataku został zaimplementowany w [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Wymaganie **preambuły uniknie optymalizacji ciągu De Bruijna** i **kody zmiennoprzecinkowe zapobiegną temu atakowi** (przy założeniu, że kod jest wystarczająco długi, aby nie można było go złamać metodą brute-force).

## Atak Sub-GHz

Aby zaatakować te sygnały za pomocą Flipper Zero, sprawdź:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Ochrona Przed Kodami Zmiennoprzecinkowymi

Automatyczne otwieracze do bram garażowych zazwyczaj używają bezprzewodowego pilota do otwierania i zamykania bramy garażowej. Pilot **wysyła sygnał radiowy (RF)** do otwieracza bramy garażowej, który uruchamia silnik do otwarcia lub zamknięcia drzwi.

Istnieje możliwość, że ktoś może użyć urządzenia znanego jako grabber kodów do przechwycenia sygnału RF i zarejestrowania go do późniejszego użycia. Jest to znane jako **atak powtórzeniowy**. Aby zapobiec tego rodzaju atakowi, wiele nowoczesnych otwieraczy do bram garażowych używa bardziej bezpiecznej metody szyfrowania znanej jako system **kodów zmiennoprzecinkowych**.

**Sygnał RF jest zazwyczaj przesyłany za pomocą kodu zmiennoprzecinkowego**, co oznacza, że kod zmienia się przy każdym użyciu. Sprawia to, że jest **trudniej** dla kogoś, aby **przechwycić** sygnał i **użyć** go do uzyskania **nieautoryzowanego** dostępu do garażu.

W systemie kodów zmiennoprzecinkowych, pilot i otwieracz do bramy garażowej mają **wspólny algorytm**, który **generuje nowy kod** za każdym razem, gdy pilot jest używany. Otwieracz bramy garażowej odpowie tylko na **poprawny kod**, co sprawia, że jest znacznie trudniej dla kogoś uzyskać nieautoryzowany dostęp do garażu, po prostu przechwytując kod.

### **Atak Brakującego Połączenia**

W zasadzie, nasłuchujesz przycisku i **przechwytujesz sygnał, gdy pilot jest poza zasięgiem** urządzenia (np. samochodu lub garażu). Następnie przenosisz się do urządzenia i **używasz przechwyconego kodu, aby je otworzyć**.

### Pełny Atak Zakłócania Połączenia

Atakujący mógłby **zakłócić sygnał w pobliżu pojazdu lub odbiornika**, aby **odbiornik faktycznie nie "słyszał" kodu**, a gdy to się zdarzy, można po prostu **przechwycić i odtworzyć** kod po zakończeniu zakłócania.

Ofiara w pewnym momencie użyje **kluczy do zablokowania samochodu**, ale wtedy atak **nagrał wystarczającą ilość kodów "zamknij drzwi"**, które być może można by ponownie wysłać, aby otworzyć drzwi (może być potrzebna **zmiana częstotliwości**, ponieważ są samochody, które używają tych samych kodów do otwierania i zamykania, ale nasłuchują obu poleceń na różnych częstotliwościach).

{% hint style="warning" %}
**Zakłócanie działa**, ale jest zauważalne, ponieważ jeśli **osoba zamykająca samochód po prostu sprawdza drzwi**, aby upewnić się, że są zamknięte, zauważy, że samochód jest otwarty. Dodatkowo, jeśli byliby świadomi takich ataków, mogliby nawet usłyszeć, że drzwi nigdy nie wydały dźwięku **blokady** ani światła samochodu nie migały, gdy nacisnęli przycisk „blokady”.
{% endhint %}

### **Atak Przechwytywania Kodów (zwany również 'RollJam')**

To bardziej **podstępna technika zakłócania**. Atakujący zakłóci sygnał, więc gdy ofiara spróbuje zamknąć drzwi, nie zadziała, ale atakujący **zarejestruje ten kod**. Następnie ofiara **spróbuje ponownie zamknąć samochód** naciskając przycisk, a samochód **zarejestruje ten drugi kod**.\
Natychmiast po tym **atakujący może wysłać pierwszy kod** i **samochód się zamknie** (ofiara myśli, że drugie naciśnięcie je zamknęło). Następnie atakujący będzie mógł **wysłać drugi skradziony kod, aby otworzyć** samochód (przy założeniu, że **kod "zamknij samochód" można również użyć do otwarcia**). Może być potrzebna zmiana częstotliwości (ponieważ są samochody, które używają tych samych kodów do otwierania i zamykania, ale nasłuchują obu poleceń na różnych częstotliwościach).

Atakujący może **zakłócić odbiornik samochodu, a nie swój odbiornik**, ponieważ jeśli odbiornik samochodu słucha na przykład w 1 MHz szerokopasmowym, atakujący nie **zakłóci** dokładnej częstotliwości używanej przez pilot, ale **bliską w tym spektrum**, podczas gdy **odbiorca atakującego będzie słuchał w mniejszym zakresie**, gdzie może słuchać sygnału pilota **bez sygnału zakłócenia**.

{% hint style="warning" %}
Inne implementacje pokazują, że **kod zmiennoprzecinkowy stanowi część** całkowitego wysłanego kodu. Innymi słowy, wysłany kod to **klucz 24 bitowy**, gdzie pierwsze **12 to kod zmiennoprzecinkowy**, drugie 8 to **polecenie** (takie jak zablokuj lub odblokuj), a ostatnie 4 to **suma kontrolna**. Pojazdy wdrażające ten typ są również naturalnie podatne, ponieważ atakujący musi jedynie zastąpić segment kodu zmiennoprzecinkowego, aby móc **użyć dowolnego kodu zmiennoprzecinkowego na obu częstotliwościach**.
{% endhint %}

{% hint style="danger" %}
Zauważ, że jeśli ofiara wyśle trzeci kod, gdy atakujący wysyła pierwszy, pierwszy i drugi kod zostaną unieważnione.
{% endhint %}
### Atak zakłócania alarmu dźwiękowego

Testowanie przeciwko systemowi kodów zmieniających zainstalowanemu w samochodzie, **wysłanie tego samego kodu dwukrotnie** natychmiast **aktywowało alarm** i immobilizer, co stwarzało unikalną możliwość **odmowy usługi**. Ironicznie, sposób **wyłączenia alarmu** i immobilizera polegał na **naciśnięciu** pilota, co dawało atakującemu możliwość **ciągłego przeprowadzania ataku DoS**. Lub połącz ten atak z **poprzednim, aby uzyskać więcej kodów**, ponieważ ofiara chciałaby jak najszybciej zatrzymać atak.

## Referencje

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
