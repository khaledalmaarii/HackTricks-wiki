# Jak działa podczerwień <a href="#jak-działa-port-podczerwieni" id="jak-działa-port-podczerwieni"></a>

**Światło podczerwone jest niewidoczne dla ludzi**. Długość fali podczerwieni wynosi od **0,7 do 1000 mikronów**. Piloty do domu używają sygnału podczerwonego do transmisji danych i działają w zakresie długości fali od 0,75 do 1,4 mikrona. Mikrokontroler w pilocie sprawia, że dioda podczerwona migocze z określoną częstotliwością, zamieniając sygnał cyfrowy w sygnał podczerwony.

Do odbierania sygnałów podczerwonych używa się **fotoodbiornika**. **Konwertuje on światło podczerwone na impulsy napięcia**, które są już **sygnałami cyfrowymi**. Zazwyczaj w odbiorniku znajduje się **filtr światła ciemnego**, który przepuszcza **tylko pożądaną długość fali** i eliminuje szum.

### Różnorodność protokołów podczerwieni <a href="#różnorodność-protokołów-podczerwieni" id="różnorodność-protokołów-podczerwieni"></a>

Protokoły podczerwieni różnią się pod względem 3 czynników:

* kodowanie bitów
* struktura danych
* częstotliwość nośna — często w zakresie 36 do 38 kHz

#### Sposoby kodowania bitów <a href="#sposoby-kodowania-bitów" id="sposoby-kodowania-bitów"></a>

**1. Kodowanie odległości impulsów**

Bity są kodowane poprzez modulację czasu trwania przestrzeni między impulsami. Szerokość samego impulsu jest stała.

<figure><img src="../../.gitbook/assets/image (292).png" alt=""><figcaption></figcaption></figure>

**2. Kodowanie szerokości impulsu**

Bity są kodowane poprzez modulację szerokości impulsu. Szerokość przestrzeni po wybuchu impulsu jest stała.

<figure><img src="../../.gitbook/assets/image (279).png" alt=""><figcaption></figcaption></figure>

**3. Kodowanie fazy**

Jest również znane jako kodowanie Manchester. Wartość logiczna jest określana przez polaryzację przejścia między wybuchem impulsu a przestrzenią. "Przejście z przestrzeni na wybuch impulsu" oznacza logiczne "0", a "wybuch impulsu na przestrzeń" oznacza logiczne "1".

<figure><img src="../../.gitbook/assets/image (631).png" alt=""><figcaption></figcaption></figure>

**4. Kombinacja powyższych i innych egzotycznych**

{% hint style="info" %}
Istnieją protokoły podczerwieni, które **starają się stać uniwersalne** dla kilku rodzajów urządzeń. Najbardziej znane to RC5 i NEC. Niestety, najbardziej znane **nie oznacza najbardziej powszechne**. W moim otoczeniu spotkałem tylko dwa pilota NEC i żadnego pilota RC5.

Producenci lubią używać swoich unikalnych protokołów podczerwieni, nawet w obrębie tego samego rodzaju urządzeń (na przykład dekodery TV). Dlatego pilota z różnych firm, a czasami z różnych modeli tej samej firmy, nie można używać z innymi urządzeniami tego samego typu.
{% endhint %}

### Badanie sygnału podczerwieni

Najbardziej niezawodnym sposobem zobaczenia, jak wygląda sygnał podczerwony z pilota, jest użycie oscyloskopu. Nie demoduluje on ani nie odwraca otrzymanego sygnału, po prostu wyświetla go "tak jak jest". Jest to przydatne do testowania i debugowania. Pokażę oczekiwany sygnał na przykładzie protokołu podczerwieni NEC.

<figure><img src="../../.gitbook/assets/image (232).png" alt=""><figcaption></figcaption></figure>

Zazwyczaj na początku zakodowanego pakietu znajduje się preambuła. Pozwala to odbiornikowi określić poziom wzmocnienia i tło. Istnieją również protokoły bez preambuły, na przykład Sharp.

Następnie przesyłane są dane. Struktura, preambuła i metoda kodowania bitów są określone przez konkretny protokół.

Protokół podczerwieni **NEC** zawiera krótki kod i kod powtórzenia, który jest wysyłany podczas naciśnięcia przycisku. Zarówno kod, jak i kod powtórzenia mają tę samą preambułę na początku.

Kod **NEC** składa się, oprócz preambuły, z bajtu adresu i bajtu numeru komendy, dzięki którym urządzenie rozumie, co ma wykonać. Bajty adresu i numeru komendy są zduplikowane z wartościami odwrotnymi, aby sprawdzić integralność transmisji. Na końcu komendy znajduje się dodatkowy bit stopu.

Kod **powtórzenia** ma "1" po preambule, co oznacza bit stopu.

Dla logicznych "0" i "1" **NEC** używa kodowania odległości impulsów: najpierw przesyłany jest wybuch impulsu, po którym następuje pauza, której długość określa wartość bitu.

### Klimatyzatory

W przeciwieństwie do innych pilotów, **klimatyzatory nie przesyłają tylko kodu naciśniętego przycisku**. Przesyłają również **wszystkie informacje** po naciśnięciu przycisku, aby zapewnić **synchronizację między urządzeniem klimatyzacyjnym a pilotem**.\
Dzięki temu unikniemy sytuacji, w której urządzenie ustawione na 20ºC zostanie zwiększone do 21ºC za pomocą jednego pilota, a następnie, gdy użyty zostanie inny pilot, który nadal ma temperaturę ustawioną na 20ºC, zwiększy on temperaturę, "zwiększając" ją do 21ºC (a nie do 22ºC, myśląc, że jest w 21ºC).

### Ataki

Możesz zaatakować podczerwień za pomocą Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Referencje

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
