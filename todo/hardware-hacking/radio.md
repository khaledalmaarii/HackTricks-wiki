# Radio

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub.**

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)to darmowy analizator sygnałów cyfrowych dla systemów GNU/Linux i macOS, zaprojektowany do wyodrębniania informacji z nieznanych sygnałów radiowych. Obsługuje różne urządzenia SDR za pomocą SoapySDR i umożliwia regulację demodulacji sygnałów FSK, PSK i ASK, dekodowanie analogowego wideo, analizę sygnałów impulsowych i słuchanie analogowych kanałów głosowych (wszystko w czasie rzeczywistym).

### Podstawowa konfiguracja

Po zainstalowaniu istnieje kilka rzeczy, które można skonfigurować.\
W ustawieniach (drugie przycisku zakładki) można wybrać **urządzenie SDR** lub **wybrać plik**, który chcesz odczytać, a także częstotliwość do syntonizacji i częstotliwość próbkowania (zalecane do 2,56Msps, jeśli twój komputer to obsługuje)\\

![](<../../.gitbook/assets/image (655) (1).png>)

W zachowaniu interfejsu GUI zaleca się włączenie kilku rzeczy, jeśli twój komputer to obsługuje:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
Jeśli zauważysz, że twój komputer nie rejestruje sygnałów, spróbuj wyłączyć OpenGL i zmniejszyć częstotliwość próbkowania.
{% endhint %}

### Zastosowania

* Aby **przechwycić pewien czas sygnału i go przeanalizować**, wystarczy nacisnąć przycisk "Push to capture" tak długo, jak jest to potrzebne.

![](<../../.gitbook/assets/image (631).png>)

* **Tuner** w SigDiggerze pomaga **lepiej przechwytywać sygnały** (ale może je również pogarszać). Najlepiej zacząć od 0 i **zwiększać go**, aż znajdziesz, że **szum** wprowadzony jest **większy** niż **poprawa sygnału**, którą potrzebujesz).

![](<../../.gitbook/assets/image (658).png>)

### Synchronizacja z kanałem radiowym

Z [**SigDiggerem** ](https://github.com/BatchDrake/SigDigger)możesz zsynchronizować się z kanałem, który chcesz odsłuchać, skonfigurować opcję "Podgląd audio pasma podstawowego", skonfigurować szerokość pasma, aby uzyskać wszystkie wysyłane informacje, a następnie ustawić tuner na poziomie przed rozpoczęciem rzeczywistego wzrostu szumu:

![](<../../.gitbook/assets/image (389).png>)

## Ciekawe sztuczki

* Gdy urządzenie wysyła serie informacji, zazwyczaj **pierwsza część będzie preambułą**, więc **nie musisz się martwić**, jeśli **nie znajdziesz tam informacji** lub jeśli występują w niej błędy.
* W ramkach informacyjnych zwykle powinieneś **znaleźć różne ramki dobrze wyrównane między nimi**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **Po odzyskaniu bitów możliwe, że będziesz musiał je w jakiś sposób przetworzyć**. Na przykład, w kodowaniu Manchester up+down będzie oznaczać 1 lub 0, a down+up będzie oznaczać drugą wartość. Więc pary 1 i 0 (ups i downs) będą prawdziwym 1 lub prawdziwym 0.
* Nawet jeśli sygnał używa kodowania Manchester (niemożliwe jest znalezienie więcej niż dwóch zer lub jedynek pod rząd), możesz **znaleźć kilka jedynek lub zer razem w preambule**!

### Odkrywanie typu modulacji za pomocą IQ

Istnieją 3 sposoby przechowywania informacji w sygnałach: modulacja **amplitudy**, **częstotliwości** lub **fazy**.\
Jeśli sprawdzasz sygnał, istnieje różne sposoby, aby spróbować dowiedzieć się, jakie metody są używane do przechowywania informacji (znajdziesz więcej sposobów poniżej), ale dobrym sposobem jest sprawdzenie wykresu IQ.

![](<../../.gitbook/assets/image (630).png>)

* **Wykrywanie AM**: Jeśli na wykresie IQ pojawiają się na przykład **2 okręgi** (prawdopodobnie jeden w 0 i drugi w innej amplitudzie), może to oznaczać, że jest to sygnał AM. Wynika to z faktu, że na wykresie IQ odległość między 0 a okręgiem to amplituda sygnału, więc łatwo jest zobaczyć różne amplitudy używane.
* **Wykrywanie PM**: Podobnie jak na poprzednim obrazku, jeśli znajdziesz małe okręgi niepowiązane między sobą, prawdopodobnie oznacza to, że używana jest modulacja fazowa. Wynika to z faktu, że na wykresie IQ kąt między punktem a 0,0 to faza sygnału, co oznacza, że używane są 4 różne fazy.
* Należy zauważyć, że jeśli informacja jest ukryta w fakcie, że zmienia się faza, a nie w samej fazie, nie zobaczysz wyraźnie różnych faz.
* **Wykrywanie FM**: IQ nie ma pola do identyfikacji częstotliwości (odległość od środka to amplituda, a kąt to faza).\
Dlatego, aby zidentyfikować FM, powinieneś **zobaczyć basically tylko okrąg** na tym wykresie.\
Ponadto, różna częstotliwość jest "reprezentowana" na wykresie IQ przez **przyspieszenie prędkości wzdłuż okręgu** (więc w SysDigger po wybraniu sygnału wykres IQ jest wypełniany, jeśli znajdziesz przyspieszenie lub zmianę kierunku w utworzonym okręgu, może to oznaczać, że jest to FM):

## Przykład AM

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Odkrywanie AM

#### Sprawdzanie obwiedni

Sprawdzając informacje AM za pomocą [**SigDiggera** ](https://github.com/BatchDrake/SigDigger)i patrząc tylko na **obwied
#### Z IQ

W tym przykładzie możesz zobaczyć, że jest **duże koło**, ale także **wiele punktów w centrum**.

![](<../../.gitbook/assets/image (640).png>)

### Uzyskaj szybkość symbolu

#### Z jednym symbolem

Wybierz najmniejszy symbol, jaki możesz znaleźć (aby mieć pewność, że to tylko 1) i sprawdź "Selection freq". W tym przypadku wynosiłoby to 1,013 kHz (czyli 1 kHz).

![](<../../.gitbook/assets/image (638) (1).png>)

#### Z grupą symboli

Możesz również określić liczbę symboli, które zamierzasz wybrać, a SigDigger obliczy częstotliwość 1 symbolu (im więcej symboli wybranych, tym lepiej prawdopodobnie). W tym scenariuszu wybrałem 10 symboli, a "Selection freq" wynosi 1,004 kHz:

![](<../../.gitbook/assets/image (635).png>)

### Uzyskaj bity

Po ustaleniu, że jest to sygnał **modulowany AM** i znając **szybkość symbolu** (i wiedząc, że w tym przypadku coś w górę oznacza 1, a coś w dół oznacza 0), bardzo łatwo jest **uzyskać bity** zakodowane w sygnale. Wybierz sygnał z informacjami, skonfiguruj próbkowanie i decyzję, a następnie naciśnij przycisk próbkowania (upewnij się, że wybrano **Amplitudę**, skonfigurowano odkrytą **szybkość symbolu** i wybrano **odzyskiwanie zegara Gadnera**):

![](<../../.gitbook/assets/image (642) (1).png>)

* **Sync to selection intervals** oznacza, że jeśli wcześniej wybrałeś interwały, aby znaleźć szybkość symbolu, ta szybkość symbolu zostanie użyta.
* **Manual** oznacza, że zostanie użyta wskazana szybkość symbolu.
* W **Fixed interval selection** określasz liczbę interwałów, które powinny zostać wybrane, a oblicza się z tego szybkość symbolu.
* **Odzyskiwanie zegara Gadnera** to zazwyczaj najlepsza opcja, ale nadal musisz podać przybliżoną szybkość symbolu.

Po naciśnięciu przycisku próbkowania pojawi się to:

![](<../../.gitbook/assets/image (659).png>)

Aby sprawić, że SigDigger zrozumie, **gdzie znajduje się zakres** przenoszenia informacji, musisz kliknąć na **niższy poziom** i przytrzymać go kliknięty, aż do największego poziomu:

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

Jeśli na przykład byłyby **4 różne poziomy amplitudy**, musiałbyś skonfigurować **Bits per symbol na 2** i wybrać od najmniejszego do największego.

Ostatecznie, **zwiększając** **Zoom** i **zmieniając rozmiar wiersza**, możesz zobaczyć bity (i możesz je wszystkie zaznaczyć i skopiować, aby uzyskać wszystkie bity):

![](<../../.gitbook/assets/image (649) (1).png>)

Jeśli sygnał ma więcej niż 1 bit na symbol (na przykład 2), SigDigger **nie ma możliwości określenia, który symbol to** 00, 01, 10, 11, dlatego użyje różnych **skali szarości**, aby przedstawić każdy z nich (i jeśli skopiujesz bity, użyje **liczb od 0 do 3**, będziesz musiał je przetworzyć).

Należy również stosować **kodowania** takie jak **Manchester**, a **up+down** może być **1 lub 0**, a down+up może być 1 lub 0. W tych przypadkach musisz **przetworzyć uzyskane wartości up (1) i down (0)**, aby zastąpić pary 01 lub 10 jako 0 lub 1.

## Przykład FM

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Odkrywanie FM

#### Sprawdzanie częstotliwości i kształtu fali

Przykład sygnału wysyłającego informacje zmodulowane w FM:

![](<../../.gitbook/assets/image (661) (1).png>)

Na poprzednim obrazie można zauważyć, że używane są **2 różne częstotliwości**, ale jeśli **obserwujesz** **kształt fali**, możesz **nie być w stanie poprawnie zidentyfikować 2 różnych częstotliwości**:

![](<../../.gitbook/assets/image (653).png>)

Dzieje się tak dlatego, że przechwytuję sygnał w obu częstotliwościach, więc jedna jest mniej więcej przeciwna do drugiej:

![](<../../.gitbook/assets/image (656).png>)

Jeśli zsynchronizowana częstotliwość jest **bliższa jednej częstotliwości niż drugiej**, łatwo można zobaczyć 2 różne częstotliwości:

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Sprawdzanie histogramu

Sprawdzając histogram częstotliwości sygnału z informacjami, łatwo można zobaczyć 2 różne sygnały:

![](<../../.gitbook/assets/image (657).png>)

W tym przypadku, jeśli sprawdzisz **histogram amplitudy**, znajdziesz **tylko jedną amplitudę**, więc **nie może to być AM** (jeśli znajdziesz wiele amplitud, może to oznaczać, że sygnał tracił moc wzdłuż kanału):

![](<../../.gitbook/assets/image (646).png>)

A to byłby histogram fazy (co bardzo wyraźnie pokazuje, że sygnał nie jest modulowany fazowo):

![](<../../.gitbook/assets/image (201) (2).png>)

#### Z IQ

IQ nie ma pola do identyfikacji częstotliwości (odległość od środka to amplituda, a kąt to faza).\
Dlatego, aby zidentyfikować FM, powinieneś **zobaczyć basically tylko koło** na tym wykresie.\
Ponadto, inna częstotliwość jest "reprezentowana" na wykresie IQ przez **przyspieszenie prędkości wzdłuż koła** (więc w SysDigger, wybierając sygnał, wykres IQ jest wypełniany, jeśli znajdziesz przyspieszenie lub zmianę kierunku na utworzonym kole, może to oznaczać, że jest to FM):

![](<../../.gitbook/assets/image (643) (1).png>)

### Uzyskaj szybkość symbolu

Możesz użyć **tej samej techniki, co w przykładzie AM**, aby uzyskać szybkość symbolu, gdy już znalazłeś częstotliwości przenoszące symbole.

### Uzyskaj bity

Możesz użyć **tej samej techniki, co w przykładzie AM**, aby uzyskać bity, gdy już **znalazłeś, że sygnał jest modulowany częstotliwością** i **szybkość symbolu**.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Uzyskaj [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**The PEASS Family**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@
