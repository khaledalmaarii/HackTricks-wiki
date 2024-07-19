# Cryptografiese/Kompressie Algoritmes

## Cryptografiese/Kompressie Algoritmes

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Identifisering van Algoritmes

As jy eindig in 'n kode **wat regte en linkse skuif, xors en verskeie wiskundige operasies** gebruik, is dit hoogs moontlik dat dit die implementering van 'n **cryptografiese algoritme** is. Hier gaan daar 'n paar maniere gewys word om die **algoritme wat gebruik word te identifiseer sonder om elke stap te moet omkeer**.

### API funksies

**CryptDeriveKey**

As hierdie funksie gebruik word, kan jy vind watter **algoritme gebruik word** deur die waarde van die tweede parameter te kontroleer:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Kyk hier na die tabel van moontlike algoritmes en hul toegewyde waardes: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Komprimeer en dekomprimeer 'n gegewe buffer van data.

**CryptAcquireContext**

Van [die dokumentasie](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Die **CryptAcquireContext** funksie word gebruik om 'n handvatsel te verkry na 'n spesifieke sleutelhouer binne 'n spesifieke cryptografiese diensverskaffer (CSP). **Hierdie teruggegee handvatsel word gebruik in oproepe na CryptoAPI** funksies wat die geselekteerde CSP gebruik.

**CryptCreateHash**

Begin die hashing van 'n stroom data. As hierdie funksie gebruik word, kan jy vind watter **algoritme gebruik word** deur die waarde van die tweede parameter te kontroleer:

![](<../../.gitbook/assets/image (376).png>)

\
Kyk hier na die tabel van moontlike algoritmes en hul toegewyde waardes: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Kode konstantes

Soms is dit regtig maklik om 'n algoritme te identifiseer danksy die feit dat dit 'n spesiale en unieke waarde moet gebruik.

![](<../../.gitbook/assets/image (370).png>)

As jy die eerste konstante in Google soek, is dit wat jy kry:

![](<../../.gitbook/assets/image (371).png>)

Daarom kan jy aanvaar dat die decompiled funksie 'n **sha256 sakrekenaar** is.\
Jy kan enige van die ander konstantes soek en jy sal (waarskynlik) dieselfde resultaat verkry.

### data inligting

As die kode geen betekenisvolle konstante het nie, kan dit wees dat dit **inligting laai vanaf die .data afdeling**.\
Jy kan toegang tot daardie data verkry, **groepeer die eerste dword** en soek daarna in Google soos ons in die vorige afdeling gedoen het:

![](<../../.gitbook/assets/image (372).png>)

In hierdie geval, as jy soek na **0xA56363C6** kan jy vind dat dit verband hou met die **tabelle van die AES algoritme**.

## RC4 **(Simmetriese Crypt)**

### Kenmerke

Dit bestaan uit 3 hoofdele:

* **Inisialisering fase/**: Skep 'n **tabel van waardes van 0x00 tot 0xFF** (256bytes in totaal, 0x100). Hierdie tabel word algemeen die **Substitusie Boks** (of SBox) genoem.
* **Scrambling fase**: Sal **deur die tabel** loop wat voorheen geskep is (lus van 0x100 iterasies, weer) en elke waarde met **semi-ewe random** bytes aanpas. Om hierdie semi-ewe random bytes te skep, word die RC4 **sleutel gebruik**. RC4 **sleutels** kan **tussen 1 en 256 bytes in lengte** wees, maar dit word gewoonlik aanbeveel dat dit meer as 5 bytes is. Gewoonlik is RC4 sleutels 16 bytes in lengte.
* **XOR fase**: Laastens, die plain-text of cyphertext word **XORed met die waardes wat voorheen geskep is**. Die funksie om te enkripteer en te dekripteer is dieselfde. Hiervoor sal 'n **lus deur die geskepte 256 bytes** uitgevoer word soveel keer as wat nodig is. Dit word gewoonlik in 'n decompiled kode erken met 'n **%256 (mod 256)**.

{% hint style="info" %}
**Om 'n RC4 in 'n disassembly/decompiled kode te identifiseer, kan jy kyk vir 2 lusse van grootte 0x100 (met die gebruik van 'n sleutel) en dan 'n XOR van die invoerdata met die 256 waardes wat voorheen in die 2 lusse geskep is, waarskynlik met 'n %256 (mod 256)**
{% endhint %}

### **Inisialisering fase/Substitusie Boks:** (Let op die nommer 256 wat as teenwoordiger gebruik word en hoe 'n 0 in elke plek van die 256 karakters geskryf word)

![](<../../.gitbook/assets/image (377).png>)

### **Scrambling Fase:**

![](<../../.gitbook/assets/image (378).png>)

### **XOR Fase:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Simmetriese Crypt)**

### **Kenmerke**

* Gebruik van **substitusie boks en opsoek tabelle**
* Dit is moontlik om **AES te onderskei danksy die gebruik van spesifieke opsoek tabel waardes** (konstantes). _Let daarop dat die **konstante** in die binêre **gestoor** kan word **of geskep** _ _**dynamies**._
* Die **enkripsiesleutel** moet **deelbaar** wees deur **16** (gewoonlik 32B) en gewoonlik word 'n **IV** van 16B gebruik.

### SBox konstantes

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Simmetriese Crypt)**

### Kenmerke

* Dit is selde om sekere malware wat dit gebruik te vind, maar daar is voorbeelde (Ursnif)
* Eenvoudig om te bepaal of 'n algoritme Serpent is of nie gebaseer op sy lengte (uiters lang funksie)

### Identifisering

In die volgende beeld let op hoe die konstante **0x9E3779B9** gebruik word (let daarop dat hierdie konstante ook deur ander crypto algoritmes soos **TEA** -Tiny Encryption Algorithm gebruik word).\
Let ook op die **grootte van die lus** (**132**) en die **aantal XOR operasies** in die **disassembly** instruksies en in die **kode** voorbeeld:

![](<../../.gitbook/assets/image (381).png>)

Soos voorheen genoem, kan hierdie kode binne enige decompiler as 'n **baie lang funksie** gesien word aangesien daar **nie spronge** binne dit is nie. Die decompiled kode kan soos volg lyk:

![](<../../.gitbook/assets/image (382).png>)

Daarom is dit moontlik om hierdie algoritme te identifiseer deur die **magiese nommer** en die **begin XORs** te kontroleer, 'n **baie lang funksie** te sien en **instruksies** van die lang funksie **met 'n implementering** te **vergelyk** (soos die skuif links deur 7 en die rotasie links deur 22).

## RSA **(Asimmetriese Crypt)**

### Kenmerke

* Meer kompleks as simmetriese algoritmes
* Daar is geen konstantes nie! (aangepaste implementasies is moeilik om te bepaal)
* KANAL (n crypto ontleder) slaag nie daarin om leidrade oor RSA te wys nie, aangesien dit op konstantes staatmaak.

### Identifisering deur vergelykings

![](<../../.gitbook/assets/image (383).png>)

* In lyn 11 (links) is daar 'n `+7) >> 3` wat dieselfde is as in lyn 35 (regs): `+7) / 8`
* Lyn 12 (links) kontroleer of `modulus_len < 0x040` en in lyn 36 (regs) kontroleer dit of `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Kenmerke

* 3 funksies: Init, Update, Final
* Soortgelyke inisialisering funksies

### Identifiseer

**Init**

Jy kan albei identifiseer deur die konstantes te kontroleer. Let daarop dat die sha\_init 'n konstante het wat MD5 nie het nie:

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transform**

Let op die gebruik van meer konstantes

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Kleiner en meer doeltreffend aangesien dit se funksie is om toevallige veranderinge in data te vind
* Gebruik opsoek tabelle (sodat jy konstantes kan identifiseer)

### Identifiseer

Kyk na **opsoek tabel konstantes**:

![](<../../.gitbook/assets/image (387).png>)

'n CRC hash algoritme lyk soos:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Kompressie)

### Kenmerke

* Nie herkenbare konstantes
* Jy kan probeer om die algoritme in python te skryf en soek na soortgelyke dinge aanlyn

### Identifiseer

Die grafiek is redelik groot:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Kyk na **3 vergelykings om dit te herken**:

![](<../../.gitbook/assets/image (384).png>)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
