# Algorytmy kryptograficzne/kompresji

## Algorytmy kryptograficzne/kompresji

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Identyfikowanie algorytmów

Jeśli natrafisz na kod **używający przesunięć w prawo i w lewo, operacji XOR i kilku operacji arytmetycznych**, bardzo możliwe, że jest to implementacja **algorytmu kryptograficznego**. W tym miejscu zostaną przedstawione sposoby **identyfikacji używanego algorytmu bez konieczności odwracania każdego kroku**.

### Funkcje API

**CryptDeriveKey**

Jeśli używana jest ta funkcja, można znaleźć, który **algorytm jest używany**, sprawdzając wartość drugiego parametru:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Sprawdź tutaj tabelę możliwych algorytmów i ich przypisanych wartości: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Kompresuje i dekompresuje dany bufor danych.

**CryptAcquireContext**

Z [dokumentacji](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Funkcja **CryptAcquireContext** służy do uzyskania uchwytu do określonego kontenera kluczy w określonym dostawcy usług kryptograficznych (CSP). **Ten zwrócony uchwyt jest używany w wywołaniach funkcji CryptoAPI**, które używają wybranego CSP.

**CryptCreateHash**

Inicjuje hashowanie strumienia danych. Jeśli używana jest ta funkcja, można znaleźć, który **algorytm jest używany**, sprawdzając wartość drugiego parametru:

![](<../../.gitbook/assets/image (376).png>)

Sprawdź tutaj tabelę możliwych algorytmów i ich przypisanych wartości: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Stałe kodu

Czasami bardzo łatwo jest zidentyfikować algorytm dzięki temu, że musi używać specjalnej i unikalnej wartości.

![](<../../.gitbook/assets/image (370).png>)

Jeśli wyszukasz pierwszą stałą w Google, otrzymasz to:

![](<../../.gitbook/assets/image (371).png>)

Dlatego można przypuszczać, że zdekompilowana funkcja to **kalkulator sha256**.\
Możesz wyszukać dowolną inną stałą i prawdopodobnie otrzymasz ten sam wynik.

### Informacje o danych

Jeśli kod nie ma żadnej istotnej stałej, może **wczytywać informacje z sekcji .data**.\
Możesz uzyskać dostęp do tych danych, **zgrupować pierwsze słowo** i wyszukać je w Google, tak jak zrobiliśmy to wcześniej w sekcji:

![](<../../.gitbook/assets/image (372).png>)

W tym przypadku, jeśli wyszukasz **0xA56363C6**, dowiesz się, że jest to związane z **tabelami algorytmu AES**.

## RC4 **(Symetryczne szyfrowanie)**

### Charakterystyka

Składa się z 3 głównych części:

* **Etap inicjalizacji/**: Tworzy **tabelę wartości od 0x00 do 0xFF** (łącznie 256 bajtów, 0x100). Ta tabela jest zwykle nazywana **Substitution Box** (lub SBox).
* **Etap mieszania**: Przejdzie **pętlą przez tabelę** utworzoną wcześniej (pętla 0x100 iteracji, ponownie) modyfikując każdą wartość za pomocą **półlosowych** bajtów. Aby utworzyć te półlosowe bajty, używany jest **klucz RC4**. Klucze RC4 mogą mieć długość od 1 do 256 bajtów, ale zwykle zaleca się, aby były powyżej 5 bajtów. Zazwyczaj klucze RC4 mają długość 16 bajtów.
* **Etap XOR**: Na koniec, tekst jawny lub tekst szyfrowany jest **XORowany z wartościami utworzonymi wcześniej**. Funkcja szyfrowania i deszyfrowania jest taka sama. W tym celu zostanie wykonana **pętla przez utworzone 256 bajtów** tak wiele razy, jak to konieczne. Zwykle jest to rozpoznawane w zdekompilowanym kodzie za pomocą **%256 (mod 256)**.

{% hint style="info" %}
**Aby zidentyfikować RC4 w kodzie disassembly/zdekompilowanym, można sprawdzić, czy istnieją 2 pętle o rozmiarze 0x100 (z użyciem klucza), a następnie XOR danych wejściowych z 256 wartościami utworzonymi wcześniej w tych 2 pętlach, prawdopodobnie używając %256 (mod 256)**
{% endhint %}

### **Etap inicjalizacji/Substitution Box:** (Zauważ liczbę 256 używaną jako licznik i jak 0 jest zapisywane na każdym miejscu z 256 znaków)

![](<../../.gitbook/assets/image (377).png>)

### **Etap mieszania:**

![](<../../.gitbook/assets/image (378).png>)

### **Etap XOR:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Symetryczne szyfrowanie)**

### **Charakterystyka**

* Używa **skrzynek substytucji i tablic wyszukiwania**
* Można **rozróżnić AES dzięki użyciu konkretnych wartości tablicy wyszukiwania** (stałych). _Zauważ, że **stała** może być **przechowywana** w postaci binarnej **lub tworzona**_ _**dynamicznie**._
* Klucz **szyfrowania** musi być **podzielny** przez **16** (zwykle 32B), a zwykle używany jest również **wektor inicjalizacyjny (IV)** o długości 16B.

### Stałe SBox

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Symetryczne szyfrowanie)**

### Charakterystyka

* Rzadko spotyka się złośliwe oprogramowanie używające tego algorytmu, ale są przykłady (Ursnif)
* Łatwo jest określić, czy algorytm jest Serpentem, na podstawie jego długości (bardzo długa funkcja)

### Identyfikacja
## RSA **(Szyfrowanie asymetryczne)**

### Charakterystyka

* Bardziej skomplikowany niż algorytmy symetryczne
* Brak stałych! (trudno określić niestandardowe implementacje)
* KANAL (kryptoanalizator) nie wykazuje wskazówek dotyczących RSA, ponieważ polega on na stałych.

### Identyfikacja przez porównania

![](<../../.gitbook/assets/image (383).png>)

* W linii 11 (lewa strona) jest `+7) >> 3`, co jest takie samo jak w linii 35 (prawa strona): `+7) / 8`
* Linia 12 (lewa strona) sprawdza, czy `modulus_len < 0x040`, a w linii 36 (prawa strona) sprawdza, czy `inputLen+11 > modulusLen`

## MD5 & SHA (funkcje skrótu)

### Charakterystyka

* 3 funkcje: Init, Update, Final
* Podobne funkcje inicjalizujące

### Identyfikacja

**Init**

Możesz je zidentyfikować, sprawdzając stałe. Zauważ, że sha\_init ma 1 stałą, której MD5 nie ma:

![](<../../.gitbook/assets/image (385).png>)

**Transformacja MD5**

Zauważ użycie większej liczby stałych

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (funkcja skrótu)

* Mniejsza i bardziej wydajna, ponieważ jej funkcją jest wykrywanie przypadkowych zmian w danych
* Używa tabel przeglądowych (dzięki czemu można zidentyfikować stałe)

### Identyfikacja

Sprawdź **stałe tabel przeglądowych**:

![](<../../.gitbook/assets/image (387).png>)

Algorytm skrótu CRC wygląda tak:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Kompresja)

### Charakterystyka

* Brak rozpoznawalnych stałych
* Możesz spróbować napisać algorytm w Pythonie i szukać podobnych rzeczy online

### Identyfikacja

Graf jest dość duży:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Sprawdź **3 porównania, aby go rozpoznać**:

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos.**

</details>
