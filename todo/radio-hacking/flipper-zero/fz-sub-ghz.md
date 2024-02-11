# FZ - Sub-GHz

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby móc je szybko naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Wprowadzenie <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero może **odbierać i nadawać częstotliwości radiowe w zakresie 300-928 MHz** za pomocą wbudowanego modułu, który może odczytywać, zapisywać i emulować piloty zdalnego sterowania. Piloty te są używane do interakcji z bramami, szlabanami, zamkami radiowymi, przełącznikami zdalnego sterowania, bezprzewodowymi dzwonkami do drzwi, inteligentnymi światłami i innymi. Flipper Zero może pomóc Ci dowiedzieć się, czy Twoje zabezpieczenia są zagrożone.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sprzęt Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ma wbudowany moduł sub-1 GHz oparty na [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[układzie CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) i antenie radiowej (maksymalny zasięg to 50 metrów). Zarówno układ CC1101, jak i antena są zaprojektowane do pracy w częstotliwościach w zakresie 300-348 MHz, 387-464 MHz i 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Działania

### Analizator częstotliwości

{% hint style="info" %}
Jak znaleźć, jaką częstotliwość używa pilot
{% endhint %}

Podczas analizowania Flipper Zero skanuje siłę sygnału (RSSI) na wszystkich dostępnych częstotliwościach w konfiguracji częstotliwości. Flipper Zero wyświetla częstotliwość o najwyższej wartości RSSI, o sile sygnału wyższej niż -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Aby ustalić częstotliwość pilota, wykonaj następujące czynności:

1. Umieść pilot bardzo blisko lewej strony Flipper Zero.
2. Przejdź do **Menu główne** **→ Sub-GHz**.
3. Wybierz **Analizator częstotliwości**, a następnie naciśnij i przytrzymaj przycisk na pilocie, który chcesz przeanalizować.
4. Sprawdź wartość częstotliwości na ekranie.

### Odczyt

{% hint style="info" %}
Znajdź informacje o używanej częstotliwości (również inny sposób znalezienia używanej częstotliwości)
{% endhint %}

Opcja **Odczyt** **nasłuchuje na skonfigurowanej częstotliwości** przy wskazanej modulacji: domyślnie 433,92 AM. Jeśli **coś zostanie znalezione** podczas odczytu, **informacja jest podawana** na ekranie. Ta informacja może być użyta do replikacji sygnału w przyszłości.

Podczas korzystania z opcji Odczyt, można nacisnąć **lewy przycisk** i go **skonfigurować**.\
W tym momencie są **4 modulacje** (AM270, AM650, FM328 i FM476), oraz **kilka istotnych częstotliwości** przechowywanych:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Możesz ustawić **dowolną, która Cię interesuje**, jednak jeśli **nie jesteś pewien, która częstotliwość** może być używana przez Twój pilot, **ustaw Hopping na ON** (domyślnie Off) i kilka razy naciśnij przycisk, aż Flipper go przechwyci i poda Ci potrzebne informacje do ustawienia częstotliwości.

{% hint style="danger" %}
Przełączanie między częstotliwościami zajmuje pewien czas, dlatego sygnały transmitowane w trakcie przełączania mogą zostać pominięte. Aby uzyskać lepszy odbiór sygnału, ustaw stałą częstotliwość określoną przez Analizator częstotliwości.
{% endhint %}

### **Odczyt surowy**

{% hint style="info" %}
Ukradnij (i odtwórz) sygnał na skonfigurowanej częstotliwości
{% endhint %}

Opcja **Odczyt surowy** **rejestruje sygnały** wysyłane na nasłuchiwanej częstotliwości. Może to być używane do **ukradnięcia** sygnału i **powtórzenia** go.

Domyślnie **Odczyt surowy również jest ustawiony na 433,92 w AM650**, ale jeśli za pomocą opcji Odczyt znalazłeś, że sygnał, który Cię interesuje, jest na **innej częstotliwości/modulacji, możesz to również zmienić** naciskając lewy przycisk (podczas korzystania z opcji Odczyt surowy).

### Brute-Force

Jeśli znasz protokół używany na przykład przez drzwi garażowe, możliwe jest **wygenerowanie wszystkich kodów i wysłanie ich za pomocą Flipper Zero**. Oto przykład, który obsługuje ogólne powszechne typy garaży: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### Dodaj ręcznie

{% hint style="info" %}
Dodaj sygnały z listy skonfigurowanych protokołów
{% endhint %}

#### Lista [obsługiwanych protokołów](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (działa z większością statycznych systemów kodowych) | 433,92 | Statyczny |
| --------------------------------------------------------------- | ------ | --------- |
| Nice Flo
### Obsługiwani dostawcy Sub-GHz

Sprawdź listę na stronie [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Obsługiwane częstotliwości według regionu

Sprawdź listę na stronie [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

{% hint style="info" %}
Otrzymaj dBm dla zapisanych częstotliwości
{% endhint %}

## Odwołanie

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby móc je szybko naprawić. Intruder śledzi Twoją powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów na GitHubie.**

</details>
