# Infrared

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Jak działa podczerwień <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Światło podczerwone jest niewidoczne dla ludzi**. Długość fali IR wynosi od **0,7 do 1000 mikronów**. Piloty domowe używają sygnału IR do przesyłania danych i działają w zakresie długości fal od 0,75 do 1,4 mikrona. Mikrokontroler w pilocie sprawia, że dioda LED podczerwieni miga z określoną częstotliwością, przekształcając sygnał cyfrowy w sygnał IR.

Aby odbierać sygnały IR, używa się **fotoreceptora**. On **przekształca światło IR w impulsy napięcia**, które są już **sygnałami cyfrowymi**. Zwykle wewnątrz odbiornika znajduje się **filtr ciemnego światła**, który przepuszcza **tylko pożądaną długość fali** i eliminuje szumy.

### Różnorodność protokołów IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Protokoły IR różnią się w 3 czynnikach:

* kodowanie bitów
* struktura danych
* częstotliwość nośna — często w zakresie 36..38 kHz

#### Sposoby kodowania bitów <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Kodowanie odległości impulsów**

Bity są kodowane przez modulację czasu trwania przestrzeni między impulsami. Szerokość samego impulsu jest stała.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Kodowanie szerokości impulsów**

Bity są kodowane przez modulację szerokości impulsu. Szerokość przestrzeni po serii impulsów jest stała.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Kodowanie fazy**

Jest również znane jako kodowanie Manchester. Wartość logiczna jest definiowana przez polaryzację przejścia między serią impulsów a przestrzenią. "Przestrzeń do serii impulsów" oznacza logikę "0", "seria impulsów do przestrzeni" oznacza logikę "1".

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombinacja poprzednich i innych egzotyków**

{% hint style="info" %}
Istnieją protokoły IR, które **próbują stać się uniwersalne** dla kilku typów urządzeń. Najbardziej znane to RC5 i NEC. Niestety, najbardziej znane **nie oznacza najbardziej powszechne**. W moim otoczeniu spotkałem tylko dwa piloty NEC i żadnego RC5.

Producenci uwielbiają używać swoich unikalnych protokołów IR, nawet w obrębie tej samej grupy urządzeń (na przykład, TV-boxy). Dlatego piloty z różnych firm, a czasami z różnych modeli tej samej firmy, nie są w stanie współpracować z innymi urządzeniami tego samego typu.
{% endhint %}

### Badanie sygnału IR

Najbardziej niezawodnym sposobem na zobaczenie, jak wygląda sygnał IR z pilota, jest użycie oscyloskopu. Nie demoduluje ani nie odwraca odebranego sygnału, jest po prostu wyświetlany "tak jak jest". To jest przydatne do testowania i debugowania. Pokażę oczekiwany sygnał na przykładzie protokołu IR NEC.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Zwykle na początku zakodowanego pakietu znajduje się preambuła. Umożliwia to odbiornikowi określenie poziomu wzmocnienia i tła. Istnieją również protokoły bez preambuły, na przykład Sharp.

Następnie przesyłane są dane. Struktura, preambuła i metoda kodowania bitów są określane przez konkretny protokół.

**Protokół IR NEC** zawiera krótki kod komendy i kod powtórzenia, który jest wysyłany podczas przytrzymywania przycisku. Zarówno kod komendy, jak i kod powtórzenia mają tę samą preambułę na początku.

**Kod komendy NEC**, oprócz preambuły, składa się z bajtu adresu i bajtu numeru komendy, dzięki którym urządzenie rozumie, co należy wykonać. Bajty adresu i numeru komendy są powielane z odwrotnymi wartościami, aby sprawdzić integralność transmisji. Na końcu komendy znajduje się dodatkowy bit stopu.

**Kod powtórzenia** ma "1" po preambule, co jest bitem stopu.

Dla **logiki "0" i "1"** NEC używa kodowania odległości impulsów: najpierw przesyłany jest impuls, po którym następuje pauza, której długość ustala wartość bitu.

### Klimatyzatory

W przeciwieństwie do innych pilotów, **klimatyzatory nie przesyłają tylko kodu naciśniętego przycisku**. Przesyłają również **wszystkie informacje**, gdy przycisk jest naciśnięty, aby zapewnić, że **urządzenie klimatyzacyjne i pilot są zsynchronizowane**.\
To zapobiegnie sytuacji, w której urządzenie ustawione na 20ºC zostanie zwiększone do 21ºC za pomocą jednego pilota, a następnie, gdy użyty zostanie inny pilot, który nadal ma temperaturę 20ºC, temperatura zostanie "zwiększona" do 21ºC (a nie do 22ºC, myśląc, że jest w 21ºC).

### Ataki

Możesz zaatakować podczerwień za pomocą Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Referencje

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
