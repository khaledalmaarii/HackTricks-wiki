# FZ - Sub-GHz

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

**Try Hard Security Group**

<figure><img src="../../../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Wprowadzenie <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero może **odbierać i nadawać częstotliwości radiowe w zakresie od 300 do 928 MHz** za pomocą wbudowanego modułu, który może odczytywać, zapisywać i emulować piloty zdalne. Te pilota służą do interakcji z bramami, szlabanami, zamkami radiowymi, przełącznikami zdalnego sterowania, dzwonkami bezprzewodowymi, inteligentnymi światłami i innymi. Flipper Zero może pomóc Ci dowiedzieć się, czy Twoje zabezpieczenia zostały naruszone.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

## Sprzęt Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero posiada wbudowany moduł sub-1 GHz oparty na układzie [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) i antenę radiową (maksymalny zasięg to 50 metrów). Zarówno układ CC1101, jak i antena są zaprojektowane do pracy w częstotliwościach w pasmach 300-348 MHz, 387-464 MHz i 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (920).png" alt=""><figcaption></figcaption></figure>

## Działania

### Analizator Częstotliwości

{% hint style="info" %}
Jak znaleźć, jaką częstotliwość używa pilot
{% endhint %}

Podczas analizy Flipper Zero skanuje siłę sygnału (RSSI) we wszystkich dostępnych częstotliwościach w konfiguracji częstotliwości. Flipper Zero wyświetla częstotliwość o najwyższej wartości RSSI, z siłą sygnału wyższą niż -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Aby określić częstotliwość pilota, wykonaj następujące czynności:

1. Umieść pilota bardzo blisko lewej strony Flipper Zero.
2. Przejdź do **Menu Główne** **→ Sub-GHz**.
3. Wybierz **Analizator Częstotliwości**, następnie przytrzymaj przycisk na pilocie, który chcesz przeanalizować.
4. Sprawdź wartość częstotliwości na ekranie.

### Odczyt

{% hint style="info" %}
Znajdź informacje o używanej częstotliwości (również inny sposób znalezienia używanej częstotliwości)
{% endhint %}

Opcja **Odczyt** **nasłuchuje na skonfigurowanej częstotliwości** przy wskazanej modulacji: domyślnie 433,92 AM. Jeśli podczas odczytu **znajdzie się coś**, informacje są wyświetlane na ekranie. Te informacje mogą być użyte w przyszłości do replikacji sygnału.

Podczas korzystania z funkcji Odczyt, można nacisnąć **lewy przycisk** i **skonfigurować go**.\
W tym momencie są **4 modulacje** (AM270, AM650, FM328 i FM476), oraz **kilka istotnych częstotliwości** przechowywanych:

<figure><img src="../../../.gitbook/assets/image (944).png" alt=""><figcaption></figcaption></figure>

Możesz ustawić **dowolną, która Cię interesuje**, jednak jeśli **nie jesteś pewien, która częstotliwość** może być używana przez pilota, **ustaw Hopping na ON** (domyślnie Off) i naciśnij przycisk kilka razy, aż Flipper ją przechwyci i poda Ci potrzebne informacje do ustawienia częstotliwości.

{% hint style="danger" %}
Przełączanie między częstotliwościami zajmuje trochę czasu, dlatego sygnały przesyłane w trakcie przełączania mogą zostać pominięte. Dla lepszego odbioru sygnału, ustaw stałą częstotliwość określoną przez Analizator Częstotliwości.
{% endhint %}

### **Odczyt Surowy**

{% hint style="info" %}
Ukradnij (i odtwórz) sygnał w skonfigurowanej częstotliwości
{% endhint %}

Opcja **Odczyt Surowy** **rejestruje sygnały** wysyłane na nasłuchiwanej częstotliwości. Można to wykorzystać do **ukradnięcia** sygnału i **powtórzenia** go.

Domyślnie **Odczyt Surowy jest również w 433,92 w AM650**, ale jeśli za pomocą opcji Odczyt znalazłeś, że sygnał, który Cię interesuje, jest w **innej częstotliwości/modulacji, możesz to również zmienić** naciskając lewy przycisk (podczas korzystania z opcji Odczyt Surowy).

### Atak Brute-Force

Jeśli znasz protokół używany na przykład przez bramę garażową, można **wygenerować wszystkie kody i wysłać je za pomocą Flipper Zero**. Jest to przykład obsługujący ogólne typy popularnych garaży: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Dodaj Ręcznie

{% hint style="info" %}
Dodaj sygnały z listy skonfigurowanych protokołów
{% endhint %}

#### Lista [obsługiwanych protokołów](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (działa z większością systemów kodów statycznych) | 433,92 | Statyczny |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433,92 | Statyczny |
| Nice Flo 24bit\_433                                             | 433,92 | Statyczny |
| CAME 12bit\_433                                                 | 433,92 | Statyczny |
| CAME 24bit\_433                                                 | 433,92 | Statyczny |
| Linear\_300                                                     | 300,00 | Statyczny |
| CAME TWEE                                                       | 433,92 | Statyczny |
| Gate TX\_433                                                    | 433,92 | Statyczny |
| DoorHan\_315                                                    | 315,00 | Dynamiczny |
| DoorHan\_433                                                    | 433,92 | Dynamiczny |
| LiftMaster\_315                                                 | 315,00 | Dynamiczny |
| LiftMaster\_390                                                 | 390,00 | Dynamiczny |
| Security+2.0\_310                                               | 310,00 | Dynamiczny |
| Security+2.0\_315                                               | 315,00 | Dynamiczny |
| Security+2.0\_390                                               | 390,00 | Dynamiczny |
### Obsługiwani dostawcy Sub-GHz

Sprawdź listę na [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Obsługiwane częstotliwości według regionów

Sprawdź listę na [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

{% hint style="info" %}
Pobierz dBm z zapisanych częstotliwości
{% endhint %}

## Odnośniki

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

**Try Hard Security Group**

<figure><img src="../../../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
