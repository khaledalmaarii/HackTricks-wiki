# Podczerwień

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Jak działa podczerwień <a href="#jak-działa-port-podczerwieni" id="jak-działa-port-podczerwieni"></a>

**Światło podczerwone jest niewidoczne dla ludzi**. Długość fali podczerwieni wynosi od **0,7 do 1000 mikronów**. Piloty do domowych urządzeń używają sygnału podczerwonego do transmisji danych i działają w zakresie długości fali od 0,75 do 1,4 mikrona. Mikrokontroler w pilocie powoduje migotanie diody podczerwonej z określoną częstotliwością, zamieniając sygnał cyfrowy w sygnał podczerwony.

Do odbierania sygnałów podczerwonych używa się **fotoodbiornika**. Przetwarza on światło podczerwone na impulsy napięciowe, które są już **sygnałami cyfrowymi**. Zazwyczaj w odbiorniku znajduje się **filtr ciemnego światła**, który przepuszcza **tylko pożądaną długość fali** i eliminuje szum.

### Różnorodność protokołów podczerwieni <a href="#różnorodność-protokołów-podczerwieni" id="różnorodność-protokołów-podczerwieni"></a>

Protokoły podczerwieni różnią się w trzech czynnikach:

* kodowanie bitów
* struktura danych
* częstotliwość nośna - często w zakresie od 36 do 38 kHz

#### Sposoby kodowania bitów <a href="#sposoby-kodowania-bitów" id="sposoby-kodowania-bitów"></a>

**1. Kodowanie odległości impulsów**

Bity są kodowane przez modulację czasu trwania przerwy między impulsami. Szerokość samego impulsu jest stała.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Kodowanie szerokości impulsu**

Bity są kodowane przez modulację szerokości impulsu. Szerokość przerwy po serii impulsów jest stała.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Kodowanie fazowe**

Jest również znane jako kodowanie Manchester. Wartość logiczna jest określana przez polarność przejścia między serią impulsów a przerwą. "Przerwa na serię impulsów" oznacza logiczne "0", "seria impulsów na przerwę" oznacza logiczne "1".

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Kombinacja powyższych i innych egzotycznych**

{% hint style="info" %}
Istnieją protokoły podczerwieni, które **starają się stać uniwersalnymi** dla kilku typów urządzeń. Najbardziej znane to RC5 i NEC. Niestety, najbardziej znane **nie oznacza najczęstsze**. W moim otoczeniu spotkałem tylko dwa pilota NEC i żadnego pilota RC5.

Producenci uwielbiają używać swoich własnych unikalnych protokołów podczerwieni, nawet w ramach tego samego zakresu urządzeń (na przykład dekodery telewizyjne). Dlatego pilota z różnych firm, a czasem nawet z różnych modeli tej samej firmy, nie można używać z innymi urządzeniami tego samego typu.
{% endhint %}

### Badanie sygnału podczerwonego

Najbardziej niezawodnym sposobem zobaczenia, jak wygląda sygnał podczerwony z pilota, jest użycie oscyloskopu. Nie demoduluje on ani nie odwraca otrzymanego sygnału, po prostu wyświetla go "tak jak jest". Jest to przydatne do testowania i debugowania. Przedstawię oczekiwany sygnał na przykładzie protokołu podczerwonego NEC.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Zazwyczaj na początku zakodowanego pakietu znajduje się preambuła. Pozwala to odbiornikowi określić poziom wzmocnienia i tło. Istnieją również protokoły bez preambuły, na przykład Sharp.

Następnie przesyłane są dane. Struktura, preambuła i sposób kodowania bitów są określone przez konkretny protokół.

**Protokół podczerwony NEC** zawiera krótką komendę i kod powtórzenia, który jest wysyłany podczas naciśnięcia przycisku. Zarówno komenda, jak i kod powtórzenia mają tę samą preambułę na początku.

**Komenda NEC**, oprócz preambuły, składa się z bajtu adresu i bajtu numeru komendy, dzięki którym urządzenie rozumie, co należy wykonać. Bajty adresu i numeru komendy są zduplikowane z odwróconymi wartościami, aby sprawdzić integralność transmisji. Na końcu komendy znajduje się dodatkowy bit stopu.

**Kod powtórzenia** ma "1" po preambule, który jest bitem stopu.

Dla logicznych "0" i "1" NEC używa kodowania odległości impulsów: najpierw przesyłana jest seria impulsów, po której następuje przerwa, jej długość określa wartość bitu.

### Klimatyzatory

W przeciwieństwie do innych pilotów, **klimatyzatory nie przesyłają tylko kodu naciśniętego przycisku**. Przesyłają również **wszystkie informacje** po naciśnięciu przycisku, aby zapewnić **synchronizację urządzenia klimatyzacyjnego i pilota**.\
Dzięki temu zapobiegnie się temu, że urządzenie ustawione na 20ºC zostanie zwiększone do 21ºC za pomocą jednego pilota, a następnie, gdy zostanie użyty inny pilot, który wciąż ma temperaturę ustawioną na 20ºC, zwiększy temperaturę do 21ºC (a nie do 22ºC, myśląc że jest w 21ºC).

### Ataki

Możesz zaatakować podczerwień za pomocą Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Odwołania

* [https://blog.flip
