# Radio

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)to darmowy analizator sygnałów cyfrowych dla systemów GNU/Linux i macOS, zaprojektowany do ekstrakcji informacji z nieznanych sygnałów radiowych. Obsługuje różne urządzenia SDR za pomocą SoapySDR, umożliwia regulowaną demodulację sygnałów FSK, PSK i ASK, dekodowanie analogowego wideo, analizę sygnałów impulsowych i słuchanie kanałów głosowych analogowych (wszystko w czasie rzeczywistym).

### Podstawowa konfiguracja

Po zainstalowaniu istnieje kilka rzeczy, które warto rozważyć skonfigurowanie.\
W ustawieniach (drugie przycisku zakładki) możesz wybrać **urządzenie SDR** lub **wybrać plik** do odczytu, ustawić częstotliwość do syntonizacji i częstotliwość próbkowania (zalecane do 2,56 Msps, jeśli twój komputer to obsługuje)\\

![](<../../.gitbook/assets/image (242).png>)

W zachowaniu interfejsu GUI zaleca się włączenie kilku rzeczy, jeśli twój komputer to obsługuje:

![](<../../.gitbook/assets/image (469).png>)

{% hint style="info" %}
Jeśli zauważysz, że twój komputer nie przechwytuje sygnałów, spróbuj wyłączyć OpenGL i zmniejszyć częstotliwość próbkowania.
{% endhint %}

### Zastosowania

* Aby **przechwycić pewien czas sygnału i go przeanalizować**, wystarczy utrzymać przycisk "Naciśnij, aby przechwycić" tak długo, jak jest to konieczne.

![](<../../.gitbook/assets/image (957).png>)

* **Tuner** w SigDigger pomaga **lepiej przechwytywać sygnały** (ale może je również pogorszyć). Idealnie zacznij od 0 i **zwiększaj go**, aż znajdziesz, że **szum** wprowadzony jest **większy** niż **poprawa sygnału**, którą potrzebujesz).

![](<../../.gitbook/assets/image (1096).png>)

### Synchronizacja z kanałem radiowym

Z [**SigDigger** ](https://github.com/BatchDrake/SigDigger)synchronizuj się z kanałem, który chcesz słuchać, skonfiguruj opcję "Podgląd audio pasma podstawowego", ustaw szerokość pasma, aby uzyskać wszystkie przesyłane informacje, a następnie ustaw tuner na poziom przed rozpoczęciem wzrostu szumu:

![](<../../.gitbook/assets/image (582).png>)

## Interesujące sztuczki

* Gdy urządzenie wysyła serie informacji, zazwyczaj **pierwsza część będzie preambułą**, więc **nie musisz się martwić**, jeśli **nie znajdziesz informacji** tam **lub jeśli występują błędy**.
* W ramkach informacyjnych zazwyczaj powinieneś **znaleźć różne ramki dobrze wyrównane między nimi**:

![](<../../.gitbook/assets/image (1073).png>)

![](<../../.gitbook/assets/image (594).png>)

* **Po odzyskaniu bitów możesz potrzebować je przetworzyć w jakiś sposób**. Na przykład w kodowaniu Manchester up+down będzie 1 lub 0, a down+up będzie drugim. Więc pary 1 i 0 (ups i downs) będą rzeczywistym 1 lub 0.
* Nawet jeśli sygnał używa kodowania Manchester (niemożliwe jest znalezienie więcej niż dwóch zer lub jedynek pod rząd), możesz **znaleźć kilka jedynek lub zer razem w preambule**!

### Odkrywanie typu modulacji za pomocą IQ

Istnieją 3 sposoby przechowywania informacji w sygnałach: Modulacja **amplitudy**, **częstotliwości** lub **fazy**.\
Jeśli sprawdzasz sygnał, istnieją różne sposoby próby ustalenia, co jest używane do przechowywania informacji (znajdź więcej sposobów poniżej), ale dobrym sposobem jest sprawdzenie wykresu IQ.

![](<../../.gitbook/assets/image (785).png>)

* **Wykrywanie AM**: Jeśli na wykresie IQ pojawią się na przykład **2 koła** (prawdopodobnie jedno w 0 i drugie o innej amplitudzie), może to oznaczać, że jest to sygnał AM. Wynika to z faktu, że na wykresie IQ odległość między 0 a kołem to amplituda sygnału, więc łatwo jest zobaczyć różne amplitudy.
* **Wykrywanie PM**: Podobnie jak na poprzednim obrazie, jeśli znajdziesz małe koła niespójne między sobą, prawdopodobnie oznacza to, że używana jest modulacja fazowa. Wynika to z faktu, że na wykresie IQ kąt między punktem a 0,0 to faza sygnału, co oznacza, że używane są 4 różne fazy.
* Zauważ, że jeśli informacja jest ukryta w zmianie fazy, a nie w samej fazie, nie zobaczysz wyraźnie różnych faz.
* **Wykrywanie FM**: IQ nie ma pola do identyfikacji częstotliwości (odległość od centrum to amplituda, a kąt to faza).\
Dlatego, aby zidentyfikować FM, powinieneś **zobaczyć praktycznie tylko koło** na tym wykresie.\
Co więcej, różna częstotliwość jest "reprezentowana" na wykresie IQ przez **przyspieszenie prędkości wzdłuż koła** (więc w SysDigger wybierając sygnał, wykres IQ jest wypełniany, jeśli znajdziesz przyspieszenie lub zmianę kierunku w utworzonym kole, może to oznaczać, że jest to FM):

## Przykład AM

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Odkrywanie AM

#### Sprawdzanie obwiedni

Sprawdzając informacje AM za pomocą [**SigDigger** ](https://github.com/BatchDrake/SigDigger)i patrząc tylko na **obwiednię**, można zobaczyć różne wyraźne poziomy amplitudy. Użyty sygnał wysyła impulsy z informacjami w AM, tak wygląda jeden impuls:

![](<../../.gitbook/assets/image (587).png>)

A tak wygląda część symbolu z przebiegiem:

![](<../../.gitbook/assets/image (731).png>)

#### Sprawdzanie histogramu

Możesz **wybrać cały sygnał**, gdzie znajdują się informacje, wybrać tryb **Amplitudy** i **Wybór** oraz kliknąć na **Histogram**. Możesz zauważyć, że znajdują się tylko 2 wyraźne poziomy

![](<../../.gitbook/assets/image (261).png>)

Na przykład, jeśli zamiast Amplitudy wybierzesz Częstotliwość w tym sygnale AM, znajdziesz tylko 1 częstotliwość (nie ma możliwości, żeby informacja modulowana w częstotliwości używała tylko 1 częstotliwości).

![](<../../.gitbook/assets/image (729).png>)

Jeśli znajdziesz wiele częstotliwości, potencjalnie nie będzie to FM, prawdopodobnie częstotliwość sygnału została zmieniona z powodu kanału.
#### Z IQ

W tym przykładzie możesz zobaczyć, że jest **duży okrąg**, ale także **wiele punktów w centrum**.

![](<../../.gitbook/assets/image (219).png>)

### Uzyskaj Szybkość Symbolu

#### Z jednym symbolem

Wybierz najmniejszy symbol, jaki znajdziesz (aby mieć pewność, że to tylko 1) i sprawdź "Częstotliwość wyboru". W tym przypadku byłoby to 1.013 kHz (czyli 1 kHz).

![](<../../.gitbook/assets/image (75).png>)

#### Z grupą symboli

Możesz także określić liczbę symboli, które zamierzasz wybrać, a SigDigger obliczy częstotliwość 1 symbolu (im więcej symboli wybranych, tym lepiej prawdopodobnie). W tym scenariuszu wybrałem 10 symboli, a "Częstotliwość wyboru" wynosi 1.004 kHz:

![](<../../.gitbook/assets/image (1005).png>)

### Uzyskaj Bity

Mając znaleziony ten sygnał **modulowany amplitudowo** i **szybkość symbolu** (i wiedząc, że w tym przypadku coś w górę oznacza 1, a coś w dół oznacza 0), bardzo łatwo jest **uzyskać bity** zakodowane w sygnale. Wybierz sygnał z informacją, skonfiguruj próbkowanie i decyzję, a następnie naciśnij próbkowanie (upewnij się, że wybrano **Amplitudę**, skonfigurowano odkrytą **Szybkość symbolu** i zaznaczono **Odzyskiwanie zegara Gadnera**):

![](<../../.gitbook/assets/image (962).png>)

* **Synchronizuj z interwałami wyboru** oznacza, że jeśli wcześniej wybrałeś interwały, aby znaleźć szybkość symbolu, ta szybkość symbolu zostanie użyta.
* **Ręczne** oznacza, że zostanie użyta wskazana szybkość symbolu.
* W **Wyborze stałego interwału** określasz liczbę interwałów, które powinny zostać wybrane, a oblicza się z nich szybkość symbolu.
* **Odzyskiwanie zegara Gadnera** to zazwyczaj najlepsza opcja, ale nadal musisz podać przybliżoną szybkość symbolu.

Po naciśnięciu próbkowania pojawi się to:

![](<../../.gitbook/assets/image (641).png>)

Teraz, aby sprawić, żeby SigDigger zrozumiał, **gdzie jest zakres** poziomu przenoszącego informacje, musisz kliknąć na **niższy poziom** i przytrzymać kliknięcie aż do największego poziomu:

![](<../../.gitbook/assets/image (436).png>)

Jeśli na przykład byłoby **4 różne poziomy amplitudy**, musiałbyś skonfigurować **Bity na symbol na 2** i wybrać od najmniejszego do największego.

Ostatecznie, **zwiększając** **Powiększenie** i **zmieniając Rozmiar wiersza**, możesz zobaczyć bity (i możesz zaznaczyć wszystko i skopiować, aby uzyskać wszystkie bity):

![](<../../.gitbook/assets/image (273).png>)

Jeśli sygnał ma więcej niż 1 bit na symbol (na przykład 2), SigDigger **nie ma możliwości określenia, który symbol to** 00, 01, 10, 11, więc użyje różnych **skal szarości** do reprezentacji każdego (i jeśli skopiujesz bity, użyje **liczb od 0 do 3**, będziesz musiał je przetworzyć).

Używaj również **kodowań** takich jak **Manchester**, gdzie **góra+dół** może być **1 lub 0**, a **dół+góra** może być 1 lub 0. W tych przypadkach musisz **przetworzyć uzyskane góry (1) i dół (0)**, aby zastąpić pary 01 lub 10 jako 0 lub 1.

## Przykład FM

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Odkrywanie FM

#### Sprawdzanie częstotliwości i kształtu fali

Przykład sygnału wysyłającego informacje zmodulowane w FM:

![](<../../.gitbook/assets/image (722).png>)

Na poprzednim obrazie można zauważyć, że **używane są 2 częstotliwości**, ale jeśli **obserwujesz** **kształt fali**, możesz **nie być w stanie poprawnie zidentyfikować 2 różnych częstotliwości**:

![](<../../.gitbook/assets/image (714).png>)

Dzieje się tak, ponieważ przechwyciłem sygnał w obu częstotliwościach, dlatego jedna jest mniej więcej przeciwna drugiej:

![](<../../.gitbook/assets/image (939).png>)

Jeśli zsynchronizowana częstotliwość jest **bliższa jednej częstotliwości niż drugiej**, można łatwo zobaczyć 2 różne częstotliwości:

![](<../../.gitbook/assets/image (419).png>)

![](<../../.gitbook/assets/image (485).png>)

#### Sprawdzanie histogramu

Sprawdzając histogram częstotliwości sygnału z informacją, można łatwo zobaczyć 2 różne sygnały:

![](<../../.gitbook/assets/image (868).png>)

W tym przypadku, jeśli sprawdzisz **histogram amplitudy**, znajdziesz **tylko jedną amplitudę**, więc **nie może to być AM** (jeśli znajdziesz wiele amplitud, może to być spowodowane utratą mocy sygnału wzdłuż kanału):

![](<../../.gitbook/assets/image (814).png>)

A to byłby histogram fazy (co bardzo wyraźnie pokazuje, że sygnał nie jest modulowany w fazie):

![](<../../.gitbook/assets/image (993).png>)

#### Z IQ

IQ nie ma pola do identyfikacji częstotliwości (odległość od centrum to amplituda, a kąt to faza).\
Dlatego, aby zidentyfikować FM, powinieneś **zobaczyć w zasadzie tylko okrąg** na tym wykresie.\
Co więcej, inna częstotliwość jest "reprezentowana" na wykresie IQ przez **przyspieszenie prędkości wzdłuż okręgu** (więc w SysDigger wybierając sygnał, wykres IQ jest wypełniany, jeśli znajdziesz przyspieszenie lub zmianę kierunku na utworzonym okręgu, może to oznaczać, że jest to FM):

![](<../../.gitbook/assets/image (78).png>)

### Uzyskaj Szybkość Symbolu

Możesz użyć **tej samej techniki, co w przykładzie AM**, aby uzyskać szybkość symbolu, gdy już znalazłeś częstotliwości przenoszące symbole.

### Uzyskaj Bity

Możesz użyć **tej samej techniki, co w przykładzie AM**, aby uzyskać bity, gdy już **znalazłeś, że sygnał jest modulowany w częstotliwości** i **szybkość symbolu**.
