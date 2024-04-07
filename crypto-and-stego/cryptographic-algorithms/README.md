# Algorytmy kryptograficzne/kompresji

## Algorytmy kryptograficzne/kompresji

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Identyfikacja algorytmów

Jeśli natrafisz na kod **korzystający z przesunięć bitowych, operacji XOR i kilku operacji arytmetycznych**, jest bardzo prawdopodobne, że jest to implementacja **algorytmu kryptograficznego**. Tutaj zostaną przedstawione sposoby **identyfikacji użytego algorytmu bez konieczności odwracania każdego kroku**.

### Funkcje API

**CryptDeriveKey**

Jeśli jest używana ta funkcja, można znaleźć, który **algorytm jest używany**, sprawdzając wartość drugiego parametru:

![](<../../.gitbook/assets/image (153).png>)

Sprawdź tutaj tabelę możliwych algorytmów i ich przypisane wartości: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Kompresuje i dekompresuje dany bufor danych.

**CryptAcquireContext**

Z [dokumentacji](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Funkcja **CryptAcquireContext** służy do uzyskania uchwytu do określonego kontenera kluczy w określonym dostawcy usług kryptograficznych (CSP). **Ten zwrócony uchwyt jest używany w wywołaniach funkcji CryptoAPI**, które korzystają z wybranego CSP.

**CryptCreateHash**

Inicjuje haszowanie strumienia danych. Jeśli jest używana ta funkcja, można znaleźć, który **algorytm jest używany**, sprawdzając wartość drugiego parametru:

![](<../../.gitbook/assets/image (546).png>)

Sprawdź tutaj tabelę możliwych algorytmów i ich przypisane wartości: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Stałe kodu

Czasami łatwo zidentyfikować algorytm dzięki konieczności użycia specjalnej i unikalnej wartości.

![](<../../.gitbook/assets/image (830).png>)

Jeśli wyszukasz pierwszą stałą w Google, otrzymasz:

![](<../../.gitbook/assets/image (526).png>)

Dlatego można założyć, że zdekompilowana funkcja to **kalkulator sha256**.\
Możesz wyszukać dowolną inną stałą i prawdopodobnie otrzymasz ten sam wynik.

### Informacje o danych

Jeśli kod nie zawiera istotnej stałej, może **wczytywać informacje z sekcji .data**.\
Możesz uzyskać dostęp do tych danych, **zgrupować pierwsze słowo** i wyszukać je w Google, tak jak zrobiliśmy wcześniej:

![](<../../.gitbook/assets/image (528).png>)

W tym przypadku, jeśli wyszukasz **0xA56363C6**, dowiesz się, że jest to związane z **tabelami algorytmu AES**.

## RC4 **(Szyfrowanie symetryczne)**

### Charakterystyka

Składa się z 3 głównych części:

* **Etap inicjalizacji/**: Tworzy **tabelę wartości od 0x00 do 0xFF** (łącznie 256 bajtów, 0x100). Ta tabela jest zwykle nazywana **Substitution Box** (lub SBox).
* **Etap mieszania**: Przejdzie **pętlą przez tabelę** utworzoną wcześniej (pętla 0x100 iteracji, ponownie) modyfikując każdą wartość za pomocą **półlosowych** bajtów. Aby utworzyć te półlosowe bajty, używany jest klucz RC4. Klucze RC4 mogą mieć długość **od 1 do 256 bajtów**, jednak zazwyczaj zaleca się, aby były one powyżej 5 bajtów. Zazwyczaj klucze RC4 mają długość 16 bajtów.
* **Etap XOR**: Wreszcie, tekst jawnie lub zaszyfrowany jest **XORowany z utworzonymi wcześniej wartościami**. Funkcja do szyfrowania i deszyfrowania jest taka sama. W tym celu zostanie wykonana **pętla przez utworzone 256 bajtów** tak wiele razy, ile jest to konieczne. Zazwyczaj jest to rozpoznawane w zdekompilowanym kodzie za pomocą **%256 (mod 256)**.

{% hint style="info" %}
**Aby zidentyfikować RC4 w kodzie disassembly/dekompilowanym, można sprawdzić 2 pętle o rozmiarze 0x100 (z użyciem klucza) i następnie XOR danych wejściowych z 256 wartościami utworzonymi wcześniej w tych 2 pętlach, prawdopodobnie z użyciem %256 (mod 256)**
{% endhint %}

### **Etap inicjalizacji/Substitution Box:** (Zauważ liczbę 256 używaną jako licznik i jak 0 jest zapisywane na każdym miejscu spośród 256 znaków)

![](<../../.gitbook/assets/image (581).png>)

### **Etap mieszania:**

![](<../../.gitbook/assets/image (832).png>)

### **Etap XOR:**

![](<../../.gitbook/assets/image (901).png>)

## **AES (Szyfrowanie symetryczne)**

### **Charakterystyka**

* Użycie **skrzynek substytucji i tabel przeglądania**
* Możliwe jest **rozróżnienie AES dzięki użyciu określonych wartości tabel przeglądania** (stałych). _Zauważ, że **stała** może być **przechowywana** w pliku binarnym **lub tworzona**_ _**dynamicznie**._
* Klucz **szyfrowania** musi być **podzielny** przez **16** (zwykle 32B), a zazwyczaj używany jest **IV** o długości 16B.

### Stałe SBox

![](<../../.gitbook/assets/image (205).png>)

## Wąż **(Szyfrowanie symetryczne)**

### Charakterystyka

* Rzadko można znaleźć złośliwe oprogramowanie używające go, ale istnieją przykłady (Ursnif)
* Łatwo określić, czy algorytm to Serpent, na podstawie jego długości (bardzo długa funkcja)

### Identyfikacja

Na poniższym obrazku zauważ, jak używana jest stała **0x9E3779B9** (zauważ, że ta stała jest również używana przez inne algorytmy kryptograficzne, takie jak **TEA** -Tiny Encryption Algorithm).\
Zauważ również **rozmiar pętli** (**132**) i **liczbę operacji XOR** w instrukcjach **disassembly** i w przykładzie **kodu**:

![](<../../.gitbook/assets/image (544).png>)

Jak wspomniano wcześniej, ten kod można zobaczyć w dowolnym dekompilatorze jako **bardzo długa funkcja**, ponieważ wewnątrz nie ma **skoków**. Zdekompilowany kod może wyglądać tak:

![](<../../.gitbook/assets/image (510).png>)

Dlatego możliwe jest zidentyfikowanie tego algorytmu, sprawdzając **numer magiczny** i **początkowe XORy**, widząc **bardzo długą funkcję** i **porównując** niektóre **instrukcje** z długiej funkcji **z implementacją** (taką jak przesunięcie w lewo o 7 i obrót w lewo o 22).
## RSA **(Szyfrowanie asymetryczne)**

### Charakterystyka

* Bardziej złożony niż algorytmy symetryczne
* Brak stałych! (trudno określić niestandardowe implementacje)
* KANAL (analizator kryptograficzny) nie wykazuje wskazówek dotyczących RSA, ponieważ polega on na stałych.

### Identyfikacja poprzez porównania

![](<../../.gitbook/assets/image (1110).png>)

* W linii 11 (lewa) jest `+7) >> 3`, co jest takie samo jak w linii 35 (prawa): `+7) / 8`
* Linia 12 (lewa) sprawdza, czy `modulus_len < 0x040`, a w linii 36 (prawa) sprawdza, czy `inputLen+11 > modulusLen`

## MD5 & SHA (funkcje skrótu)

### Charakterystyka

* 3 funkcje: Inicjalizacja, Aktualizacja, Końcowa
* Podobne funkcje inicjalizacji

### Identyfikacja

**Inicjalizacja**

Możesz je zidentyfikować, sprawdzając stałe. Zauważ, że sha\_init ma 1 stałą, której MD5 nie ma:

![](<../../.gitbook/assets/image (403).png>)

**Transformacja MD5**

Zauważ użycie większej liczby stałych

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC (funkcja skrótu)

* Mniejsza i bardziej wydajna, ponieważ jej funkcją jest znalezienie przypadkowych zmian w danych
* Korzysta z tabel poszukiwań (dzięki czemu można zidentyfikować stałe)

### Identyfikacja

Sprawdź **stałe tabeli poszukiwań**:

![](<../../.gitbook/assets/image (505).png>)

Algorytm funkcji skrótu CRC wygląda tak:

![](<../../.gitbook/assets/image (387).png>)

## APLib (Kompresja)

### Charakterystyka

* Stałe nie są rozpoznawalne
* Możesz spróbować napisać algorytm w języku Python i szukać podobnych rzeczy online

### Identyfikacja

Graf jest dość duży:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Sprawdź **3 porównania, aby go rozpoznać**:

![](<../../.gitbook/assets/image (427).png>)
