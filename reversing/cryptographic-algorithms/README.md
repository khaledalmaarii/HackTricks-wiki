# Kriptografiese/Samepersingsalgoritmes

## Kriptografiese/Samepersingsalgoritmes

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Identifisering van Algoritmes

As jy in 'n kode **eindig wat skuifregs en -links, XOR's en verskeie rekenkundige bewerkings** gebruik, is dit baie moontlik dat dit die implementering van 'n **kriptografiese algoritme** is. Hier sal 'n paar maniere getoon word om die algoritme te **identifiseer sonder om elke stap om te keer**.

### API-funksies

**CryptDeriveKey**

As hierdie funksie gebruik word, kan jy vind watter **algoritme gebruik word** deur die waarde van die tweede parameter te ondersoek:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Kyk hier na die tabel van moontlike algoritmes en hul toegewysde waardes: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Kompresseer en dekompresseer 'n gegewe databuffer.

**CryptAcquireContext**

Vanaf [die dokumentasie](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Die **CryptAcquireContext**-funksie word gebruik om 'n handvatsel te bekom na 'n spesifieke sleutelhouer binne 'n spesifieke kriptografiese diensverskaffer (CSP). **Hierdie teruggekeerde handvatsel word gebruik in oproepe na CryptoAPI-funksies** wat die gekose CSP gebruik.

**CryptCreateHash**

Begin die hasing van 'n stroom data. As hierdie funksie gebruik word, kan jy vind watter **algoritme gebruik word** deur die waarde van die tweede parameter te ondersoek:

![](<../../.gitbook/assets/image (376).png>)

Kyk hier na die tabel van moontlike algoritmes en hul toegewysde waardes: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Kodekonstantes

Soms is dit baie maklik om 'n algoritme te identifiseer dankie aan die feit dat dit 'n spesiale en unieke waarde moet gebruik.

![](<../../.gitbook/assets/image (370).png>)

As jy soek na die eerste konstante in Google, is dit wat jy kry:

![](<../../.gitbook/assets/image (371).png>)

Daarom kan jy aanneem dat die gedekomponeerde funksie 'n **sha256-kalkulator** is.\
Jy kan enige van die ander konstantes soek en jy sal waarskynlik dieselfde resultaat kry.

### data-inligting

As die kode nie enige beduidende konstantes het nie, laai dit dalk **inligting van die .data-afdeling**.\
Jy kan daardie data **toegang**, die **eerste dword groepeer** en soek daarna in Google soos ons in die vorige afdeling gedoen het:

![](<../../.gitbook/assets/image (372).png>)

In hierdie geval, as jy soek na **0xA56363C6**, kan jy vind dat dit verband hou met die **tabelle van die AES-algoritme**.

## RC4 **(Simmetriese Kriptografie)**

### Kenmerke

Dit bestaan uit 3 hoofdele:

* **Inisialiseringstadium/**: Skep 'n **tabel van waardes van 0x00 tot 0xFF** (totaal 256 byte, 0x100). Hierdie tabel word gewoonlik die **Vervangingstabel** (of SBox) genoem.
* **Verwarringstadium**: Sal deur die vooraf geskepte tabel loop (weer 'n lus van 0x100 iterasies) en elke waarde wysig met **semi-willekeurige** byte. Om hierdie semi-willekeurige byte te skep, word die RC4 **sleutel gebruik**. RC4-sleutels kan **tussen 1 en 256 byte lank** wees, maar dit word gewoonlik aanbeveel dat dit meer as 5 byte is. Gewoonlik is RC4-sleutels 16 byte lank.
* **XOR-stadium**: Uiteindelik word die oorspronklike teks of siferteks **XOR met die vooraf geskepte waardes**. Die funksie om te enkripteer en dekripteer is dieselfde. Hiervoor sal 'n **lus deur die geskepte 256 byte** uitgevoer word soveel keer as nodig. Dit word gewoonlik herken in 'n gedekomponeerde kode met 'n **%256 (mod 256)**.

{% hint style="info" %}
**Om 'n RC4 in 'n disassemblage/gedekomponeerde kode te identifiseer, kan jy kyk vir 2 lusse van grootte 0x100 (met die gebruik van 'n sleutel) en dan 'n XOR van die insetdata met die 256 waardes wat voorheen in die 2 lusse geskep is, waarskynlik met behulp van 'n %256 (mod 256)**
{% endhint %}

### **Inisialiseringstadium/Vervangingstabel:** (Let op die getal 256 wat as teller gebruik word en hoe 'n 0 in elke plek van die 256 karakters geskryf word)

![](<../../.gitbook/assets/image (377).png>)

### **Verwarringstadium:**

![](<../../.gitbook/assets/image (378).png>)

### **XOR-stadium:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Simmetriese Kriptografie)**

### **Kenmerke**

* Gebruik van **vervangingstabelle en opsoektabelle**
* Dit is moontlik om AES te **onderskei deur die gebruik van spesifieke opsoektabelwaardes** (konstantes). _Let daarop dat die **konstante** in die binêre **geberg** of **dinamies geskep** kan word._
* Die **enkripsiesleutel** moet deur **16 deelbaar** wees (gewoonlik 32B) en gewoonlik word 'n **IV** van 16B gebruik.

### SBox-konstantes

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Simmetriese Kriptografie)**

### Kenmerke

* Dit is selde om kwaadwillige sagteware te vind wat dit gebruik, maar daar is voorbeelde (Ursnif)
* Dit is maklik om te bepaal of 'n algoritme Serpent is of nie op grond van sy lengte (uiters lang funksie)

### Identifisering

Let in die volgende prentjie daarop hoe die konstante **0x9E3779B9** gebruik word (let daarop dat hierdie konstante ook deur ander kripto-algoritmes soos **TEA** - Tiny Encryption Algorithm gebruik word).\
Let ook op die **grootte van die l
## RSA **(Asimmetriese Kriptografie)**

### Kenmerke

* Meer kompleks as simmetriese algoritmes
* Daar is geen konstantes nie! (aangepaste implementasies is moeilik om te bepaal)
* KANAL (‘n kripto-analiseerder) kan nie RSA aanwysings gee nie, omdat dit afhang van konstantes.

### Identifisering deur vergelykings

![](<../../.gitbook/assets/image (383).png>)

* In lyn 11 (links) is daar ‘n `+7) >> 3` wat dieselfde is as in lyn 35 (regs): `+7) / 8`
* Lyn 12 (links) kyk of `modulus_len < 0x040` en in lyn 36 (regs) kyk dit of `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Kenmerke

* 3 funksies: Init, Update, Final
* Soortgelyke inisialiseerfunksies

### Identifiseer

**Init**

Jy kan albei identifiseer deur die konstantes te kyk. Let daarop dat sha\_init een konstante het wat MD5 nie het nie:

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transformeer**

Let op die gebruik van meer konstantes

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Kleiner en meer doeltreffend omdat dit ontwerp is om toevallige veranderinge in data te vind
* Gebruik soektabelle (sodat jy konstantes kan identifiseer)

### Identifiseer

Kyk na **soektabelkonstantes**:

![](<../../.gitbook/assets/image (387).png>)

‘n CRC-hash-algoritme lyk soos:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Kompresie)

### Kenmerke

* Nie herkenbare konstantes nie
* Jy kan probeer om die algoritme in Python te skryf en soek na soortgelyke dinge aanlyn

### Identifiseer

Die grafiek is baie groot:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Kyk na **3 vergelykings om dit te herken**:

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
