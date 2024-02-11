# Sztuczki do rozwiązywania zadań z szyfrowania w Crypto CTFs

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**The PEASS Family**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Bazy danych online z haszami

* _**Wyszukaj w Google**_
* [http://hashtoolkit.com/reverse-hash?hash=4d186321c1a7f0f354b297e8914ab240](http://hashtoolkit.com/reverse-hash?hash=4d186321c1a7f0f354b297e8914ab240)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com)
* [https://crackstation.net/](https://crackstation.net)
* [https://md5decrypt.net/](https://md5decrypt.net)
* [https://www.onlinehashcrack.com](https://www.onlinehashcrack.com)
* [https://gpuhash.me/](https://gpuhash.me)
* [https://hashes.org/search.php](https://hashes.org/search.php)
* [https://www.cmd5.org/](https://www.cmd5.org)
* [https://hashkiller.co.uk/Cracker/MD5](https://hashkiller.co.uk/Cracker/MD5)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html)

## Magiczne narzędzia do automatycznego rozwiązywania

* [**https://github.com/Ciphey/Ciphey**](https://github.com/Ciphey/Ciphey)
* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/) (moduł Magic)
* [https://github.com/dhondta/python-codext](https://github.com/dhondta/python-codext)
* [https://www.boxentriq.com/code-breaking](https://www.boxentriq.com/code-breaking)

## Kodery

Większość zakodowanych danych można odkodować za pomocą tych 2 zasobów:

* [https://www.dcode.fr/tools-list](https://www.dcode.fr/tools-list)
* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### Automatyczne rozwiązywanie podstawień

* [https://www.boxentriq.com/code-breaking/cryptogram](https://www.boxentriq.com/code-breaking/cryptogram)
* [https://quipqiup.com/](https://quipqiup.com) - Bardzo dobre!

#### Szyfr Cezara - Automatyczne rozwiązywanie ROTx

* [https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)

#### Szyfr Atbash

* [http://rumkin.com/tools/cipher/atbash.php](http://rumkin.com/tools/cipher/atbash.php)

### Automatyczne rozwiązywanie kodowań bazowych

Sprawdź wszystkie te bazy za pomocą: [https://github.com/dhondta/python-codext](https://github.com/dhondta/python-codext)

* **Ascii85**
* `BQ%]q@psCd@rH0l`
* **Base26** \[_A-Z_]
* `BQEKGAHRJKHQMVZGKUXNT`
* **Base32** \[_A-Z2-7=_]
* `NBXWYYLDMFZGCY3PNRQQ====`
* **Zbase32** \[_ybndrfg8ejkmcpqxot1uwisza345h769_]
* `pbzsaamdcf3gna5xptoo====`
* **Base32 Geohash** \[_0-9b-hjkmnp-z_]
* `e1rqssc3d5t62svgejhh====`
* **Base32 Crockford** \[_0-9A-HJKMNP-TV-Z_]
* `D1QPRRB3C5S62RVFDHGG====`
* **Base32 Extended Hexadecimal** \[_0-9A-V_]
* `D1NMOOB3C5P62ORFDHGG====`
* **Base45** \[_0-9A-Z $%\*+-./:_]
* `59DPVDGPCVKEUPCPVD`
* **Base58 (bitcoin)** \[_1-9A-HJ-NP-Za-km-z_]
* `2yJiRg5BF9gmsU6AC`
* **Base58 (flickr)** \[_1-9a-km-zA-HJ-NP-Z_]
* `2YiHqF5bf9FLSt6ac`
* **Base58 (ripple)** \[_rpshnaf39wBUDNEGHJKLM4PQ-T7V-Z2b-eCg65jkm8oFqi1tuvAxyz_]
* `pyJ5RgnBE9gm17awU`
* **Base62** \[_0-9A-Za-z_]
* `g2AextRZpBKRBzQ9`
* **Base64** \[_A-Za-z0-9+/=_]
* `aG9sYWNhcmFjb2xh`
* **Base67** \[_A-Za-z0-9-_.!\~\_]
* `NI9JKX0cSUdqhr!p`
* **Base85 (Ascii85)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `BQ%]q@psCd@rH0l`
* **Base85 (Adobe)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `<~BQ%]q@psCd@rH0l~>`
* **Base85 (IPv6 or RFC1924)** \[_0-9A-Za-z!#$%&()\*+-;<=>?@^_\`{|}\~\_]
* `Xm4y`V\_|Y(V{dF>\`
* **Base85 (xbtoa)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `xbtoa Begin\nBQ%]q@psCd@rH0l\nxbtoa End N 12 c E 1a S 4e6 R 6991d`
* **Base85 (XML)** \[_0-9A-Za-y!#$()\*+,-./:;=?@^\`{|}\~z\__]
* `Xm4y|V{~Y+V}dF?`
* **Base91** \[_A-Za-z0-9!#$%&()\*+,./:;<=>?@\[]^\_\`{|}\~"_]
*
* `DmPsv8J7qrlKEoY7`
* **MEGAN35** \[_3G-Ub=c-pW-Z/12+406-9Vaq-zA-F5_]
* `kLD8iwKsigSalLJ5`
* **ZONG22** \[_ZKj9n+yf0wDVX1s/5YbdxSo=ILaUpPBCHg8uvNO4klm6iJGhQ7eFrWczAMEq3RTt2_]
* `ayRiIo1gpO+uUc7g`
* **ESAB46** \[]
* `3sHcL2NR8WrT7mhR`
* **MEGAN45** \[]
* `kLD8igSXm2KZlwrX`
* **TIGO3FX** \[]
* `7AP9mIzdmltYmIP9mWXX`
* **TRIPO5** \[]
* `UE9vSbnBW6psVzxB`
* **FERON74** \[]
* `PbGkNudxCzaKBm0x`
* **GILA7** \[]
* `D+nkv8C1qIKMErY1`
* **Citrix CTX1** \[]
* `MNGIKCAHMOGLKPAKMMGJKNAINPHKLOBLNNHILCBHNOHLLPBK`

[http://k4.cba.pl/dw/crypo/tools/eng\_atom128c.html](http://k4.cba.pl/dw/crypo/tools/eng\_atom128c.html) - 404 Dead: [https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html)

### HackerizeXS \[_╫Λ↻├☰┏_]
```
╫☐↑Λ↻Λ┏Λ↻☐↑Λ
```
* [http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html) - 404 Nie znaleziono: [https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html)

### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
* [http://k4.cba.pl/dw/crypo/tools/eng\_morse-encode.html](http://k4.cba.pl/dw/crypo/tools/eng\_morse-encode.html) - 404 Nie znaleziono: [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### UUencoder
```
begin 644 webutils_pl
M2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(
M3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/
F3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$$`
`
end
```
* [http://www.webutils.pl/index.php?idx=uu](http://www.webutils.pl/index.php?idx=uu)

### XXEncoder

XXEncoder jest narzędziem do kodowania i dekodowania danych w formacie XXEncoded. Jest to popularna metoda kodowania, która konwertuje dane binarne na tekst, aby można je było bezpiecznie przesyłać lub przechowywać. XXEncoder używa zestawu 64 znaków, które reprezentują różne wartości binarne. 

Aby skorzystać z XXEncoder, wystarczy wprowadzić dane, które chcesz zakodować lub zdekodować, a następnie kliknąć przycisk "Encode" lub "Decode". Wynik zostanie wyświetlony w polu tekstowym. 

XXEncoder jest przydatnym narzędziem podczas rozwiązywania zadań związanych z kodowaniem w CTF-ach (Capture The Flag). Może być również używany do analizy i manipulacji danych kodowanych w formacie XXEncoded.
```
begin 644 webutils_pl
hG2xAEIVDH236Hol-G2xAEIVDH236Hol-G2xAEIVDH236Hol-G2xAEIVDH236
5Hol-G2xAEE++
end
```
* [www.webutils.pl/index.php?idx=xx](https://github.com/carlospolop/hacktricks/tree/bf578e4c5a955b4f6cdbe67eb4a543e16a3f848d/crypto/www.webutils.pl/index.php?idx=xx)

### YEncoder

YEncoder to prosty algorytm kodowania, który jest często stosowany w CTF-ach (Capture The Flag) i innych zabezpieczeniowych konkursach. Algorytm ten jest podobny do Base64, ale ma kilka różnic.

#### Sposób działania

YEncoder koduje dane w postaci sekwencji znaków ASCII. Każdy znak jest reprezentowany przez 8 bitów. Algorytm działa w następujący sposób:

1. Podziel dane na bloki po 3 bajty.
2. Dla każdego bloku, podziel go na 4 grupy po 6 bitów.
3. Przekonwertuj każdą grupę 6-bitową na wartość dziesiętną.
4. Przekonwertuj wartość dziesiętną na odpowiadający jej znak ASCII.
5. Połącz wszystkie znaki ASCII w jedną sekwencję.

#### Przykład

Załóżmy, że mamy dane wejściowe "Hello". Pierwszym krokiem jest przekształcenie tych danych na postać binarną:

```
H -> 01001000
e -> 01100101
l -> 01101100
l -> 01101100
o -> 01101111
```

Następnie, dane są podzielone na bloki po 3 bajty:

```
01001000 01100101 01101100
01101100 01101111
```

Każdy blok jest podzielony na grupy po 6 bitów:

```
010010 000110 010101 101100
011011 000110 111101
```

Każda grupa 6-bitowa jest przekonwertowana na wartość dziesiętną:

```
18 6 21 44
27 6 61
```

Wartości dziesiętne są przekonwertowane na odpowiadające im znaki ASCII:

```
R G V ,
W G 9
```

Ostatecznie, wszystkie znaki ASCII są połączone w jedną sekwencję:

```
RGV,WG9
```

#### Dekodowanie

Dekodowanie danych zakodowanych za pomocą YEncoder odbywa się w odwrotny sposób. Każdy znak ASCII jest przekonwertowany na odpowiadającą mu wartość dziesiętną, a następnie na grupę 6-bitową. Grupy 6-bitowe są łączone w bloki po 3 bajty, a ostatecznie otrzymuje się oryginalne dane.

#### Narzędzia online

Można znaleźć wiele narzędzi online do kodowania i dekodowania danych za pomocą YEncoder. Wystarczy wprowadzić dane wejściowe i narzędzie automatycznie przeprowadzi operację kodowania lub dekodowania.
```
=ybegin line=128 size=28 name=webutils_pl
ryvkryvkryvkryvkryvkryvkryvk
=yend size=28 crc32=35834c86
```
* [http://www.webutils.pl/index.php?idx=yenc](http://www.webutils.pl/index.php?idx=yenc)

### BinHex
```
(This file must be converted with BinHex 4.0)
:#hGPBR9dD@acAh"X!$mr2cmr2cmr!!!!!!!8!!!!!-ka5%p-38K26%&)6da"5%p
-38K26%'d9J!!:
```
* [http://www.webutils.pl/index.php?idx=binhex](http://www.webutils.pl/index.php?idx=binhex)

### ASCII85

ASCII85 to kodowanie znaków, które konwertuje dane binarne na tekst ASCII. Jest podobne do kodowania Base64, ale bardziej efektywne w zakresie przesyłania danych binarnych. W ASCII85 każde 4 bajty danych binarnych są zamieniane na 5 znaków ASCII.

Przykład:

```
Dane binarne: 01100001 01100010 01100011 01100100
ASCII85: 6&DL
```

ASCII85 jest często używane w zabezpieczeniach, kompresji danych i w niektórych formatach plików, takich jak PDF.
```
<~85DoF85DoF85DoF85DoF85DoF85DoF~>
```
* [http://www.webutils.pl/index.php?idx=ascii85](http://www.webutils.pl/index.php?idx=ascii85)

### Klawiatura Dvoraka
```
drnajapajrna
```
* [https://www.geocachingtoolbox.com/index.php?lang=pl\&page=dvorakKeyboard](https://www.geocachingtoolbox.com/index.php?lang=pl\&page=dvorakKeyboard)

### A1Z26

Litery na ich wartość numeryczną
```
8 15 12 1 3 1 18 1 3 15 12 1
```
### Szyfr afiniczny - kodowanie

Litera na numer `(ax+b)%26` (_a_ i _b_ to klucze, a _x_ to litera) i wynik z powrotem na literę
```
krodfdudfrod
```
### Kod SMS

**Multitap** [zamienia literę](https://www.dcode.fr/word-letter-change) na powtarzające się cyfry zdefiniowane przez odpowiadający kod klawisza na klawiaturze [telefonu komórkowego](https://www.dcode.fr/phone-keypad-cipher) (Ten tryb jest używany podczas pisania SMS-ów).\
Na przykład: 2=A, 22=B, 222=C, 3=D...\
Możesz zidentyfikować ten kod, ponieważ zobaczysz\*\* wiele powtarzających się liczb\*\*.

Możesz odkodować ten kod na stronie: [https://www.dcode.fr/multitap-abc-cipher](https://www.dcode.fr/multitap-abc-cipher)

### Kod Bacona

Zamień każdą literę na 4 litery A lub B (lub 1 i 0)
```
00111 01101 01010 00000 00010 00000 10000 00000 00010 01101 01010 00000
AABBB ABBAB ABABA AAAAA AAABA AAAAA BAAAA AAAAA AAABA ABBAB ABABA AAAAA
```
### Runy

![](../.gitbook/assets/runes.jpg)

## Kompresja

**Raw Deflate** i **Raw Inflate** (można znaleźć oba w Cyberchef) mogą kompresować i dekompresować dane bez nagłówków.

## Proste szyfrowanie

### XOR - Automatyczne rozwiązanie

* [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### Bifid

Wymagane jest hasło
```
fgaargaamnlunesuneoa
```
### Vigenere

Wymagane jest hasło kluczowe.
```
wodsyoidrods
```
* [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)
* [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
* [https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx](https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx)

## Silne szyfrowanie

### Fernet

2 ciągi base64 (token i klucz)
```
Token:
gAAAAABWC9P7-9RsxTz_dwxh9-O2VUB7Ih8UCQL1_Zk4suxnkCvb26Ie4i8HSUJ4caHZuiNtjLl3qfmCv_fS3_VpjL7HxCz7_Q==

Key:
-s6eI5hyNh8liH7Gq0urPC-vzPgNnxauKvRO4g03oYI=
```
* [https://asecuritysite.com/encryption/ferdecode](https://asecuritysite.com/encryption/ferdecode)

### Podział tajemnicy Samira

Tajemnica jest dzielona na X części, a do jej odzyskania potrzebne jest Y części (_Y <=X_).
```
8019f8fa5879aa3e07858d08308dc1a8b45
80223035713295bddf0b0bd1b10a5340b89
803bc8cf294b3f83d88e86d9818792e80cd
```
[http://christian.gen.co/secrets/](http://christian.gen.co/secrets/)

### Brute-force OpenSSL

* [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
* [https://github.com/carlospolop/easy\_BFopensslCTF](https://github.com/carlospolop/easy\_BFopensslCTF)

## Narzędzia

* [https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
* [https://github.com/lockedbyte/cryptovenom](https://github.com/lockedbyte/cryptovenom)
* [https://github.com/nccgroup/featherduster](https://github.com/nccgroup/featherduster)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
