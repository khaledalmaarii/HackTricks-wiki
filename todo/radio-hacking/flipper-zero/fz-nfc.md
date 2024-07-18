# FZ - NFC

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

## Wprowadzenie <a href="#id-9wrzi" id="id-9wrzi"></a>

Aby uzyskać informacje o RFID i NFC, sprawdź następującą stronę:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Obsługiwane karty NFC <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Oprócz kart NFC, Flipper Zero obsługuje **inny typ kart wysokiej częstotliwości**, takich jak kilka **Mifare** Classic i Ultralight oraz **NTAG**.
{% endhint %}

Nowe typy kart NFC będą dodawane do listy obsługiwanych kart. Flipper Zero obsługuje następujące **karty NFC typu A** (ISO 14443A):

* ﻿**Karty bankowe (EMV)** — tylko odczyt UID, SAK i ATQA bez zapisywania.
* ﻿**Nieznane karty** — odczyt (UID, SAK, ATQA) i emulacja UID.

Dla **kart NFC typu B, F i V**, Flipper Zero jest w stanie odczytać UID bez zapisywania go.

### Karty NFC typu A <a href="#uvusf" id="uvusf"></a>

#### Karta bankowa (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero może tylko odczytać UID, SAK, ATQA i zapisane dane na kartach bankowych **bez zapisywania**.

Ekran odczytu karty bankowej. Dla kart bankowych Flipper Zero może tylko odczytać dane **bez zapisywania i emulowania ich**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Nieznane karty <a href="#id-37eo8" id="id-37eo8"></a>

Gdy Flipper Zero jest **niezdolny do określenia typu karty NFC**, wtedy można odczytać tylko **UID, SAK i ATQA**.

Ekran odczytu nieznanej karty. Dla nieznanych kart NFC Flipper Zero może emulować tylko UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Karty NFC typu B, F i V <a href="#wyg51" id="wyg51"></a>

Dla **kart NFC typu B, F i V**, Flipper Zero może tylko **odczytać i wyświetlić UID** bez zapisywania go.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Akcje

Aby uzyskać wprowadzenie do NFC [**przeczytaj tę stronę**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Odczyt

Flipper Zero może **odczytać karty NFC**, jednak **nie rozumie wszystkich protokołów** opartych na ISO 14443. Jednakże, ponieważ **UID jest atrybutem niskiego poziomu**, możesz znaleźć się w sytuacji, gdy **UID jest już odczytany, ale protokół transferu danych na wyższym poziomie jest nadal nieznany**. Możesz odczytać, emulować i ręcznie wprowadzić UID, używając Flippera dla prymitywnych czytników, które używają UID do autoryzacji.

#### Odczyt UID VS Odczyt Danych Wewnątrz <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

W Flipperze, odczyt tagów 13.56 MHz można podzielić na dwie części:

* **Odczyt niskiego poziomu** — odczytuje tylko UID, SAK i ATQA. Flipper próbuje zgadnąć protokół na wyższym poziomie na podstawie tych danych odczytanych z karty. Nie możesz być w 100% pewny, ponieważ jest to tylko przypuszczenie oparte na pewnych czynnikach.
* **Odczyt wysokiego poziomu** — odczytuje dane z pamięci karty, używając konkretnego protokołu na wyższym poziomie. To byłoby odczytywanie danych z Mifare Ultralight, odczytywanie sektorów z Mifare Classic lub odczytywanie atrybutów karty z PayPass/Apple Pay.

### Odczyt Specyficzny

W przypadku, gdy Flipper Zero nie jest w stanie znaleźć typu karty na podstawie danych niskiego poziomu, w `Dodatkowych Akcjach` możesz wybrać `Odczytaj Specyficzny Typ Karty` i **ręcznie** **określić typ karty, którą chcesz odczytać**.

#### Karty Bankowe EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Oprócz prostego odczytu UID, możesz wyodrębnić znacznie więcej danych z karty bankowej. Możliwe jest **uzyskanie pełnego numeru karty** (16 cyfr na przedniej stronie karty), **daty ważności**, a w niektórych przypadkach nawet **nazwy właściciela** wraz z listą **najnowszych transakcji**.\
Jednak nie **możesz odczytać CVV w ten sposób** (3 cyfry na odwrocie karty). Również **karty bankowe są chronione przed atakami powtórzeniowymi**, więc skopiowanie ich za pomocą Flippera, a następnie próba emulacji w celu zapłaty za coś, nie zadziała.

## Odnośniki

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

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
