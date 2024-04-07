<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA ČLANSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks merch**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>


# Identifikacija pakovanih binarnih fajlova

* **Nedostatak stringova**: Često je moguće primetiti da pakovani binarni fajlovi gotovo da nemaju stringova
* Veliki broj **neiskorišćenih stringova**: Takođe, kada zlonamerni softver koristi neku vrstu komercijalnog pakera, često se može primetiti veliki broj stringova bez međusobnih referenci. Čak i ako ti stringovi postoje, to ne znači da binarni fajl nije pakovan.
* Možete koristiti alate kako biste pokušali da otkrijete koji paker je korišćen za pakovanje binarnog fajla:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Osnovne Preporuke

* **Počnite** analiziranje pakovanog binarnog fajla **odozdo u IDA-i i idite nagore**. Unpackeri završavaju kada završi otpakirani kod, tako da je malo verovatno da će unpacker preneti izvršenje na otpakirani kod na početku.
* Potražite **JMP-ove** ili **CALL-ove** ka **registrima** ili **regionima** **memorije**. Takođe potražite **funkcije koje guraju argumente i adresu pravca, a zatim pozivaju `retn`**, jer će povratak funkcije u tom slučaju možda pozvati adresu koja je upravo gurnuta na stek pre poziva.
* Postavite **prekidnu tačku** na `VirtualAlloc` jer ovo alocira prostor u memoriji gde program može pisati otpakirani kod. "Pokreni do korisničkog koda" ili koristite F8 da **dođete do vrednosti unutar EAX-a** nakon izvršenja funkcije i "**pratite tu adresu u dump-u**". Nikad ne znate da li je to region gde će se sačuvati otpakirani kod.
* **`VirtualAlloc`** sa vrednošću "**40**" kao argument znači Read+Write+Execute (neki kod koji zahteva izvršenje će biti kopiran ovde).
* Dok otpakujete kod, normalno je pronaći **više poziva** ka **aritmetičkim operacijama** i funkcijama poput **`memcopy`** ili **`Virtual`**`Alloc`. Ako se nađete u funkciji koja očigledno obavlja samo aritmetičke operacije i možda neki `memcopy`, preporuka je da pokušate da **pronađete kraj funkcije** (možda JMP ili poziv nekom registru) **ili** barem **poziv poslednje funkcije** i pokrenete se do nje jer kod nije interesantan.
* Dok otpakujete kod, **obratite pažnju** svaki put kada **promenite region memorije** jer promena regiona memorije može ukazivati na **početak otpakivanja koda**. Možete lako dumpovati region memorije koristeći Process Hacker (proces --> svojstva --> memorija).
* Pokušavajući da otpakujete kod, dobar način da **znate da li već radite sa otpakiranim kodom** (tako da ga samo dumpujete) je da **proverite stringove binarnog fajla**. Ako u nekom trenutku izvršite skok (možda promenite region memorije) i primetite da je **dodato mnogo više stringova**, tada možete znati **da radite sa otpakiranim kodom**.\
Međutim, ako paket već sadrži mnogo stringova, možete videti koliko stringova sadrži reč "http" i videti da li se taj broj povećava.
* Kada dumpujete izvršni fajl iz regiona memorije, možete popraviti neke zaglavlja koristeći [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).


<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA ČLANSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks merch**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
