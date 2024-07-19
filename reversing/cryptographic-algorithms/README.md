# Algorytmy kryptograficzne/kompresji

## Algorytmy kryptograficzne/kompresji

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## Identyfikacja algorytmów

Jeśli kończysz w kodzie **używając przesunięć w prawo i w lewo, xorów i kilku operacji arytmetycznych**, jest bardzo prawdopodobne, że jest to implementacja **algorytmu kryptograficznego**. Poniżej przedstawione zostaną sposoby na **identyfikację algorytmu, który jest używany bez potrzeby odwrotnego inżynierowania każdego kroku**.

### Funkcje API

**CryptDeriveKey**

Jeśli ta funkcja jest używana, możesz znaleźć, który **algorytm jest używany**, sprawdzając wartość drugiego parametru:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Sprawdź tutaj tabelę możliwych algorytmów i ich przypisanych wartości: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Kompresuje i dekompresuje dany bufor danych.

**CryptAcquireContext**

Z [dokumentacji](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Funkcja **CryptAcquireContext** jest używana do uzyskania uchwytu do konkretnego kontenera kluczy w ramach konkretnego dostawcy usług kryptograficznych (CSP). **Ten zwrócony uchwyt jest używany w wywołaniach funkcji CryptoAPI**, które korzystają z wybranego CSP.

**CryptCreateHash**

Inicjuje haszowanie strumienia danych. Jeśli ta funkcja jest używana, możesz znaleźć, który **algorytm jest używany**, sprawdzając wartość drugiego parametru:

![](<../../.gitbook/assets/image (376).png>)

\
Sprawdź tutaj tabelę możliwych algorytmów i ich przypisanych wartości: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Stałe kodu

Czasami naprawdę łatwo jest zidentyfikować algorytm dzięki temu, że musi używać specjalnej i unikalnej wartości.

![](<../../.gitbook/assets/image (370).png>)

Jeśli wyszukasz pierwszą stałą w Google, oto co otrzymasz:

![](<../../.gitbook/assets/image (371).png>)

Dlatego możesz założyć, że zdekompilowana funkcja to **kalkulator sha256.**\
Możesz wyszukać dowolną z innych stałych, a prawdopodobnie uzyskasz ten sam wynik.

### Informacje o danych

Jeśli kod nie ma żadnej znaczącej stałej, może być **ładowany informacje z sekcji .data**.\
Możesz uzyskać dostęp do tych danych, **zgrupować pierwszy dword** i wyszukać go w Google, jak zrobiliśmy w poprzedniej sekcji:

![](<../../.gitbook/assets/image (372).png>)

W tym przypadku, jeśli poszukasz **0xA56363C6**, możesz znaleźć, że jest to związane z **tabelami algorytmu AES**.

## RC4 **(Kryptografia symetryczna)**

### Cechy

Składa się z 3 głównych części:

* **Etap inicjalizacji/**: Tworzy **tabelę wartości od 0x00 do 0xFF** (łącznie 256 bajtów, 0x100). Ta tabela jest powszechnie nazywana **Substitution Box** (lub SBox).
* **Etap mieszania**: Będzie **przechodzić przez tabelę** utworzoną wcześniej (pętla 0x100 iteracji, ponownie) modyfikując każdą wartość za pomocą **półlosowych** bajtów. Aby stworzyć te półlosowe bajty, używany jest klucz RC4. Klucze RC4 mogą mieć **od 1 do 256 bajtów długości**, jednak zazwyczaj zaleca się, aby miały więcej niż 5 bajtów. Zwykle klucze RC4 mają długość 16 bajtów.
* **Etap XOR**: Na koniec, tekst jawny lub szyfrogram jest **XORowany z wartościami utworzonymi wcześniej**. Funkcja do szyfrowania i deszyfrowania jest taka sama. W tym celu zostanie wykonana **pętla przez utworzone 256 bajtów** tyle razy, ile to konieczne. Zwykle jest to rozpoznawane w zdekompilowanym kodzie z **%256 (mod 256)**.

{% hint style="info" %}
**Aby zidentyfikować RC4 w kodzie disassembly/zdekompilowanym, możesz sprawdzić 2 pętle o rozmiarze 0x100 (z użyciem klucza), a następnie XOR danych wejściowych z 256 wartościami utworzonymi wcześniej w 2 pętlach, prawdopodobnie używając %256 (mod 256)**
{% endhint %}

### **Etap inicjalizacji/Substitution Box:** (Zauważ liczbę 256 używaną jako licznik i jak 0 jest zapisywane w każdym miejscu 256 znaków)

![](<../../.gitbook/assets/image (377).png>)

### **Etap mieszania:**

![](<../../.gitbook/assets/image (378).png>)

### **Etap XOR:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Kryptografia symetryczna)**

### **Cechy**

* Użycie **tabel substytucji i tabel wyszukiwania**
* Możliwe jest **rozróżnienie AES dzięki użyciu specyficznych wartości tabel wyszukiwania** (stałych). _Zauważ, że **stała** może być **przechowywana** w binarnym **lub tworzona** _**dynamicznie**._
* **Klucz szyfrowania** musi być **podzielny** przez **16** (zwykle 32B) i zazwyczaj używa się **IV** o długości 16B.

### Stałe SBox

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Kryptografia symetryczna)**

### Cechy

* Rzadko można znaleźć złośliwe oprogramowanie używające go, ale są przykłady (Ursnif)
* Łatwo określić, czy algorytm to Serpent, czy nie, na podstawie jego długości (ekstremalnie długa funkcja)

### Identyfikacja

Na poniższym obrazie zauważ, jak stała **0x9E3779B9** jest używana (zauważ, że ta stała jest również używana przez inne algorytmy kryptograficzne, takie jak **TEA** - Tiny Encryption Algorithm).\
Zauważ także **rozmiar pętli** (**132**) i **liczbę operacji XOR** w instrukcjach **disassembly** oraz w przykładzie **kodu**:

![](<../../.gitbook/assets/image (381).png>)

Jak wspomniano wcześniej, ten kod może być wizualizowany w dowolnym dekompilatorze jako **bardzo długa funkcja**, ponieważ **nie ma skoków** w jej wnętrzu. Zdekompilowany kod może wyglądać następująco:

![](<../../.gitbook/assets/image (382).png>)

Dlatego możliwe jest zidentyfikowanie tego algorytmu, sprawdzając **magiczną liczbę** i **początkowe XOR-y**, widząc **bardzo długą funkcję** i **porównując** niektóre **instrukcje** długiej funkcji **z implementacją** (jak przesunięcie w lewo o 7 i obrót w lewo o 22).

## RSA **(Kryptografia asymetryczna)**

### Cechy

* Bardziej złożone niż algorytmy symetryczne
* Nie ma stałych! (trudno określić niestandardowe implementacje)
* KANAL (analityk kryptograficzny) nie pokazuje wskazówek dotyczących RSA, ponieważ opiera się na stałych.

### Identyfikacja przez porównania

![](<../../.gitbook/assets/image (383).png>)

* W linii 11 (po lewej) jest `+7) >> 3`, co jest takie samo jak w linii 35 (po prawej): `+7) / 8`
* Linia 12 (po lewej) sprawdza, czy `modulus_len < 0x040`, a w linii 36 (po prawej) sprawdza, czy `inputLen+11 > modulusLen`

## MD5 i SHA (hash)

### Cechy

* 3 funkcje: Init, Update, Final
* Podobne funkcje inicjalizacyjne

### Identyfikacja

**Init**

Możesz zidentyfikować obie, sprawdzając stałe. Zauważ, że sha\_init ma 1 stałą, której MD5 nie ma:

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transform**

Zauważ użycie większej liczby stałych

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Mniejszy i bardziej wydajny, ponieważ jego funkcją jest znajdowanie przypadkowych zmian w danych
* Używa tabel wyszukiwania (więc możesz zidentyfikować stałe)

### Identyfikacja

Sprawdź **stałe tabeli wyszukiwania**:

![](<../../.gitbook/assets/image (387).png>)

Algorytm haszujący CRC wygląda jak:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Kompresja)

### Cechy

* Nie rozpoznawalne stałe
* Możesz spróbować napisać algorytm w Pythonie i poszukać podobnych rzeczy w Internecie

### Identyfikacja

Wykres jest dość duży:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Sprawdź **3 porównania, aby go rozpoznać**:

![](<../../.gitbook/assets/image (384).png>)

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
