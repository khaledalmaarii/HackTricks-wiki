# iButton

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## Wprowadzenie

iButton to ogólna nazwa elektronicznego klucza identyfikacyjnego zapakowanego w **metalowy pojemnik w kształcie monety**. Nazywany jest również **Dallas Touch** Memory lub pamięcią kontaktową. Chociaż często błędnie określany jako klucz „magnetyczny”, nie ma w nim **nic magnetycznego**. W rzeczywistości wewnątrz ukryty jest pełnoprawny **mikrochip** działający na protokole cyfrowym.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### Czym jest iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Zazwyczaj iButton odnosi się do fizycznej formy klucza i czytnika - okrągłej monety z dwoma stykami. Dla otaczającej go ramki istnieje wiele wariantów, od najczęstszych plastikowych uchwytów z otworem po pierścienie, wisiorki itp.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Gdy klucz dotrze do czytnika, **styki stykają się** i klucz jest zasilany, aby **przesłać** swoje ID. Czasami klucz **nie jest odczytywany** od razu, ponieważ **PSD styku domofonu jest większy** niż powinien być. W takim przypadku zewnętrzne kontury klucza i czytnika nie mogły się dotknąć. Jeśli tak się stanie, będziesz musiał przycisnąć klucz do jednej ze ścian czytnika.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protokół 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Klucze Dallas wymieniają dane za pomocą protokołu 1-wire. Zaledwie jeden styk do transferu danych (!!) w obu kierunkach, od mastera do slave'a i odwrotnie. Protokół 1-wire działa zgodnie z modelem Master-Slave. W tej topologii Master zawsze inicjuje komunikację, a Slave podąża za jego instrukcjami.

Gdy klucz (Slave) kontaktuje się z domofonem (Master), chip wewnątrz klucza włącza się, zasilany przez domofon, a klucz jest inicjowany. Następnie domofon żąda ID klucza. Następnie przyjrzymy się temu procesowi bardziej szczegółowo.

Flipper może działać zarówno w trybie Master, jak i Slave. W trybie odczytu klucza Flipper działa jako czytnik, to znaczy działa jako Master. A w trybie emulacji klucza, flipper udaje klucz, jest w trybie Slave.

### Klucze Dallas, Cyfral i Metakom

Aby uzyskać informacje na temat działania tych kluczy, sprawdź stronę [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Ataki

iButtony mogą być atakowane za pomocą Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Odniesienia

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
