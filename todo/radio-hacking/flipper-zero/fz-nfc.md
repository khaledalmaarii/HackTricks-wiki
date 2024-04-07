# FZ - NFC

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Wprowadzenie <a href="#id-9wrzi" id="id-9wrzi"></a>

Aby uzyskać informacje na temat RFID i NFC, sprawdź następującą stronę:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Obsługiwane karty NFC <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Oprócz kart NFC Flipper Zero obsługuje **inne typy kart o wysokiej częstotliwości**, takie jak kilka kart **Mifare** Classic i Ultralight oraz **NTAG**.
{% endhint %}

Nowe typy kart NFC zostaną dodane do listy obsługiwanych kart. Flipper Zero obsługuje następujące **typy kart NFC typu A** (ISO 14443A):

* ﻿**Karty bankowe (EMV)** — tylko odczytuje UID, SAK i ATQA bez zapisywania.
* ﻿**Nieznane karty** — odczytuje (UID, SAK, ATQA) i emuluje UID.

Dla **kart NFC typu B, typu F i typu V**, Flipper Zero jest w stanie odczytać UID bez zapisywania go.

### Karty NFC typu A <a href="#uvusf" id="uvusf"></a>

#### Karta bankowa (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero może jedynie odczytać UID, SAK, ATQA i dane przechowywane na kartach bankowych **bez zapisywania**.

Ekran odczytu kart bankowychDla kart bankowych, Flipper Zero może jedynie odczytać dane **bez zapisywania i emulowania**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Nieznane karty <a href="#id-37eo8" id="id-37eo8"></a>

Kiedy Flipper Zero jest **niezdolny do określenia typu karty NFC**, wtedy można jedynie **odczytać i zapisać** UID, SAK i ATQA.

Ekran odczytu nieznanej karty NFCDla nieznanych kart NFC, Flipper Zero może emulować jedynie UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Typy kart NFC B, F i V <a href="#wyg51" id="wyg51"></a>

Dla **kart NFC typu B, F i V**, Flipper Zero może jedynie **odczytać i wyświetlić UID** bez zapisywania go.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Działania

Dla wprowadzenia w temat NFC [**przeczytaj tę stronę**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Odczyt

Flipper Zero może **odczytywać karty NFC**, jednakże **nie rozumie wszystkich protokołów** opartych na ISO 14443. Ponieważ jednak **UID to atrybut na niskim poziomie**, możesz znaleźć się w sytuacji, gdy **UID jest już odczytane, ale protokół transferu danych na wysokim poziomie jest nadal nieznany**. Możesz odczytywać, emulować i ręcznie wprowadzać UID za pomocą Flippera dla czytników prymitywnych, które używają UID do autoryzacji.

#### Odczytanie UID VS Odczytanie Danych Wewnątrz <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (214).png" alt=""><figcaption></figcaption></figure>

W Flipperze odczyt tagów 13,56 MHz można podzielić na dwie części:

* **Odczyt na niskim poziomie** — odczytuje jedynie UID, SAK i ATQA. Flipper próbuje zgadnąć protokół na wysokim poziomie na podstawie tych danych odczytanych z karty. Nie można być w 100% pewnym, ponieważ jest to tylko założenie oparte na określonych czynnikach.
* **Odczyt na wysokim poziomie** — odczytuje dane z pamięci karty za pomocą określonego protokołu na wysokim poziomie. Byłoby to odczytanie danych z Mifare Ultralight, odczytanie sektorów z Mifare Classic lub odczytanie atrybutów karty z PayPass/Apple Pay.

### Odczytanie Konkretne

W przypadku gdy Flipper Zero nie jest w stanie określić typu karty na podstawie danych na niskim poziomie, w `Dodatkowe Działania` można wybrać `Odczytaj Konkretny Typ Karty` i **ręcznie** **określić typ karty, który chcesz odczytać**.

#### Karty Bankowe EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Oprócz zwykłego odczytu UID, można wyciągnąć znacznie więcej danych z karty bankowej. Możliwe jest **uzyskanie pełnego numeru karty** (16 cyfr na przodzie karty), **daty ważności** oraz w niektórych przypadkach nawet **imię właściciela** wraz z listą **najnowszych transakcji**.\
Jednak **nie można w ten sposób odczytać CVV** (3 cyfry na odwrocie karty). Ponadto **karty bankowe są chronione przed atakami typu replay**, więc skopiowanie jej za pomocą Flippera i próba emulacji do zapłacenia czegoś nie zadziała.
## Odnośniki

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Zacznij naukę hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
