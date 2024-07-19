# FZ - Infrared

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## Wprowadzenie <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Aby uzyskać więcej informacji na temat działania podczerwieni, sprawdź:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Odbiornik sygnału IR w Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper używa cyfrowego odbiornika sygnału IR TSOP, który **pozwala na przechwytywanie sygnałów z pilotów IR**. Istnieją niektóre **smartfony** jak Xiaomi, które również mają port IR, ale pamiętaj, że **większość z nich może tylko przesyłać** sygnały i jest **niezdolna do ich odbierania**.

Odbiornik podczerwieni Flippera **jest dość czuły**. Możesz nawet **złapać sygnał**, pozostając **gdzieś pomiędzy** pilotem a telewizorem. Nie ma potrzeby, aby celować pilotem bezpośrednio w port IR Flippera. To jest przydatne, gdy ktoś zmienia kanały, stojąc blisko telewizora, a zarówno ty, jak i Flipper jesteście w pewnej odległości.

Ponieważ **dekodowanie sygnału podczerwieni** odbywa się po stronie **oprogramowania**, Flipper Zero potencjalnie wspiera **odbiór i transmisję dowolnych kodów pilotów IR**. W przypadku **nieznanych** protokołów, które nie mogły zostać rozpoznane - **nagrywa i odtwarza** surowy sygnał dokładnie tak, jak został odebrany.

## Akcje

### Uniwersalne piloty

Flipper Zero może być używany jako **uniwersalny pilot do sterowania dowolnym telewizorem, klimatyzatorem lub centrum multimedialnym**. W tym trybie Flipper **bruteforcuje** wszystkie **znane kody** wszystkich wspieranych producentów **zgodnie ze słownikiem z karty SD**. Nie musisz wybierać konkretnego pilota, aby wyłączyć telewizor w restauracji.

Wystarczy nacisnąć przycisk zasilania w trybie Uniwersalnego Pilota, a Flipper **sekwencyjnie wyśle komendy "Power Off"** do wszystkich telewizorów, które zna: Sony, Samsung, Panasonic... i tak dalej. Gdy telewizor odbierze swój sygnał, zareaguje i wyłączy się.

Taki brute-force zajmuje czas. Im większy słownik, tym dłużej to potrwa. Niemożliwe jest ustalenie, który sygnał dokładnie telewizor rozpoznał, ponieważ nie ma informacji zwrotnej z telewizora.

### Nauka nowego pilota

Możliwe jest **przechwycenie sygnału podczerwieni** za pomocą Flipper Zero. Jeśli **znajdzie sygnał w bazie danych**, Flipper automatycznie **będzie wiedział, jakie to urządzenie** i pozwoli ci z nim interagować.\
Jeśli nie, Flipper może **zapisać** **sygnał** i pozwoli ci **go odtworzyć**.

## Odnośniki

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
