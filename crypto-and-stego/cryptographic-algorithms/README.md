# Kriptografiese/Samepressingsalgoritmes

## Kriptografiese/Samepressingsalgoritmes

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Identifisering van Algoritmes

As jy eindig in 'n kode **wat skuifregte en -links, xors en verskeie rekenkundige bewerkings** gebruik, is dit baie moontlik dat dit die implementering van 'n **kriptografiese algoritme** is. Hier sal 'n paar maniere getoon word om die algoritme wat gebruik word te **identifiseer sonder om elke stap om te keer**.

### API-funksies

**CryptDeriveKey**

As hierdie funksie gebruik word, kan jy vind watter **algoritme gebruik word** deur die waarde van die tweede parameter te kontroleer:

![](<../../.gitbook/assets/image (156).png>)

Kyk hier na die tabel van moontlike algoritmes en hul toegewysde waardes: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Druk 'n gegewe buffer van data saam en maak dit weer los.

**CryptAcquireContext**

Van [die dokumente](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Die **CryptAcquireContext**-funksie word gebruik om 'n handvatsel te bekom na 'n spesifieke sleutelhouer binne 'n spesifieke kriptografiese diensverskaffer (CSP). **Hierdie teruggekeerde handvatsel word gebruik in oproepe na CryptoAPI**-funksies wat die gekose CSP gebruik.

**CryptCreateHash**

Begin die hasjing van 'n stroom data. As hierdie funksie gebruik word, kan jy vind watter **algoritme gebruik word** deur die waarde van die tweede parameter te kontroleer:

![](<../../.gitbook/assets/image (549).png>)

Kyk hier na die tabel van moontlike algoritmes en hul toegewysde waardes: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Kodekonstantes

Dikwels is dit baie maklik om 'n algoritme te identifiseer danksy die feit dat dit 'n spesiale en unieke waarde moet gebruik.

![](<../../.gitbook/assets/image (833).png>)

As jy soek na die eerste konstante op Google, is dit wat jy kry:

![](<../../.gitbook/assets/image (529).png>)

Daarom kan jy aanneem dat die gedekomponeerde funksie 'n **sha256-kalkulator** is.\
Jy kan enige van die ander konstantes soek en jy sal (waarskynlik) dieselfde resultaat kry.

### Data-inligting

As die kode nie enige beduidende konstante het nie, kan dit wees dat dit **inligting laai van die .data-afdeling**.\
Jy kan daardie data **toegang**, **die eerste d-woord groepeer** en daarnaar soek op Google soos ons in die vorige afdeling gedoen het:

![](<../../.gitbook/assets/image (531).png>)

In hierdie geval, as jy soek na **0xA56363C6** kan jy vind dat dit verband hou met die **tabelle van die AES-algoritme**.

## RC4 **(Simmetriese Kript)**

### Kenmerke

Dit bestaan uit 3 hoofdele:

* **Inisialiseringstadium/**: Skep 'n **tabel van waardes van 0x00 tot 0xFF** (totaal 256 byte, 0x100). Hierdie tabel word gewoonlik **Substitusieboks** (of SBox) genoem.
* **Verwarringsstadium**: Sal deur die tabel **loop** wat voorheen geskep is (loop van 0x100 iterasies, weer) en elke waarde wysig met **semi-willekeurige** byte. Om hierdie semi-willekeurige byte te skep, word die RC4-**sleutel gebruik**. RC4-**sleutels** kan **tussen 1 en 256 byte lank** wees, maar dit word gewoonlik aanbeveel dat dit meer as 5 byte is. Gewoonlik is RC4-sleutels 16 byte lank.
* **XOR-stadium**: Laastens word die platte teks of siferteks **XORed met die waardes wat voorheen geskep is**. Die funksie om te enkripteer en dekripteer is dieselfde. Hiervoor sal 'n **loop deur die geskepte 256 byte** soveel keer uitgevoer word as wat nodig is. Dit word gewoonlik herken in 'n gedekomponeerde kode met 'n **%256 (mod 256)**.

{% hint style="info" %}
**Om 'n RC4 in 'n disassemblage/gedekomponeerde kode te identifiseer, kan jy kyk vir 2 lusse van grootte 0x100 (met die gebruik van 'n sleutel) en dan 'n XOR van die insetdata met die 256 waardes wat voorheen in die 2 lusse geskep is, waarskynlik met behulp van 'n %256 (mod 256)**
{% endhint %}

### **Inisialiseringstadium/Substitusieboks:** (Let op die nommer 256 wat as teller gebruik word en hoe 'n 0 in elke plek van die 256 karakters geskryf word)

![](<../../.gitbook/assets/image (584).png>)

### **Verwarringsstadium:**

![](<../../.gitbook/assets/image (835).png>)

### **XOR-stadium:**

![](<../../.gitbook/assets/image (904).png>)

## **AES (Simmetriese Kript)**

### **Kenmerke**

* Gebruik van **substitusiebokse en opsoektabelle**
* Dit is moontlik om AES te **onderskei danksy die gebruik van spesifieke opsoektabelwaardes** (konstantes). _Let daarop dat die **konstante** in die binêre lêer **gestoor** kan word _of **dinamies geskep**_._
* Die **enkripsiesleutel** moet **deelbaar** wees deur **16** (gewoonlik 32B) en gewoonlik word 'n **IV** van 16B gebruik.

### SBox-konstantes

![](<../../.gitbook/assets/image (208).png>)

## Serpent **(Simmetriese Kript)**

### Kenmerke

* Dit is skaars om 'n paar kwaadwillige programme te vind wat dit gebruik, maar daar is voorbeelde (Ursnif)
* Dit is maklik om te bepaal of 'n algoritme Serpent is of nie gebaseer op sy lengte (uiters lang funksie)

### Identifisering

Let in die volgende beeld op hoe die konstante **0x9E3779B9** gebruik word (let daarop dat hierdie konstante ook deur ander kripto-algoritmes soos **TEA** -Tiny Encryption Algorithm gebruik word).\
Let ook op die **grootte van die lus** (**132**) en die **aantal XOR-operasies** in die **disassemblage-instruksies** en in die **kodevoorbeeld**:

![](<../../.gitbook/assets/image (547).png>)

Soos voorheen genoem is, kan hierdie kode binne enige dekompiler gesien word as 'n **baie lang funksie** omdat daar **geen spronge** binne-in is nie. Die gedekomponeerde kode kan lyk soos die volgende:

![](<../../.gitbook/assets/image (513).png>)

Daarom is dit moontlik om hierdie algoritme te identifiseer deur die **sielkundige nommer** en die **aanvanklike XORs** te kontroleer, 'n **baie lang funksie** te sien en sommige **instruksies** van die lang funksie te **vergelyk** met 'n implementering (soos die skuif links met 7 en die draai links met 22).
## RSA **(Asimmetriese Kriptografie)**

### Kenmerke

* Meer kompleks as simmetriese algoritmes
* Daar is geen konstantes nie! (aangepaste implementasies is moeilik om te bepaal)
* KANAL (‘n kripto-analiseerder) misluk om wenke oor RSA te toon aangesien dit op konstantes staatmaak.

### Identifisering deur vergelykings

![](<../../.gitbook/assets/image (1113).png>)

* In lyn 11 (links) is daar ‘n `+7) >> 3` wat dieselfde is as in lyn 35 (regs): `+7) / 8`
* Lyn 12 (links) kontroleer of `modulus_len < 0x040` en in lyn 36 (regs) kontroleer dit of `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Kenmerke

* 3 funksies: Init, Update, Final
* Soortgelyke inisialiseerfunksies

### Identifiseer

**Init**

Jy kan albei identifiseer deur die konstantes te kontroleer. Let daarop dat die sha\_init 1 konstante het wat MD5 nie het nie:

![](<../../.gitbook/assets/image (406).png>)

**MD5 Transformeer**

Let op die gebruik van meer konstantes

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC (hash)

* Kleiner en meer doeltreffend aangesien dit ontworpe is om toevallige veranderinge in data te vind
* Gebruik opsoektabelle (sodat jy konstantes kan identifiseer)

### Identifiseer

Kontroleer **opsoektabel konstantes**:

![](<../../.gitbook/assets/image (508).png>)

‘n CRC-hash-algoritme lyk soos:

![](<../../.gitbook/assets/image (391).png>)

## APLib (Kompresie)

### Kenmerke

* Nie-herkenbare konstantes
* Jy kan probeer om die algoritme in Python te skryf en soek na soortgelyke dinge aanlyn

### Identifiseer

Die grafiek is redelik groot:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Kontroleer **3 vergelykings om dit te herken**:

![](<../../.gitbook/assets/image (430).png>)
