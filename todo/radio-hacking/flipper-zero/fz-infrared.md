# FZ - Infrared

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristupiti **najnovijoj verziji PEASS ili preuzeti HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repozitorijum**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijum**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Uvod <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Za više informacija o tome kako Infrared funkcioniše, pogledajte:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## IR Signal Receiver u Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper koristi digitalni IR signalni prijemnik TSOP, koji **omogućava presretanje signala sa IR daljinskih upravljača**. Postoje neki **pametni telefoni** poput Xiaomija, koji takođe imaju IR port, ali imajte na umu da **većina njih može samo da emituje** signale i **nije u mogućnosti da ih primi**.

Flipperov infracrveni **prijemnik je prilično osetljiv**. Možete čak **uhvatiti signal** dok ste **negde između** daljinskog upravljača i televizora. Nije potrebno usmeravati daljinski upravljač direktno ka Flipperovom IR portu. Ovo je korisno kada neko menja kanale dok stoji blizu televizora, a vi i Flipper ste udaljeni.

Kako se **dekodiranje infracrvenog** signala dešava na **softverskoj** strani, Flipper Zero potencijalno podržava **prijem i slanje bilo kojih IR kodova daljinskog upravljača**. U slučaju **nepoznatih** protokola koji nisu mogli biti prepoznati - on **snima i reprodukuje** sirovi signal tačno onako kako je primljen.

## Akcije

### Univerzalni daljinski upravljači

Flipper Zero može se koristiti kao **univerzalni daljinski upravljač za kontrolu bilo kog televizora, klima uređaja ili multimedijalnog centra**. U ovom režimu, Flipper **bruteforsira** sve **poznate kodove** svih podržanih proizvođača **prema rečniku sa SD kartice**. Ne morate odabrati određeni daljinski upravljač da biste isključili televizor u restoranu.

Dovoljno je pritisnuti dugme za napajanje u režimu Univerzalnog daljinskog upravljača, i Flipper će **sekvencijalno slati "Isključi"** komande svim televizorima koje poznaje: Sony, Samsung, Panasonic... i tako dalje. Kada televizor primi svoj signal, reagovaće i isključiti se.

Takav brute-force zahteva vreme. Što je veći rečnik, to će duže trajati da se završi. Nemoguće je saznati koji signal tačno je televizor prepoznao jer nema povratne informacije od televizora.

### Nauči novi daljinski upravljač

Moguće je **uhvatiti infracrveni signal** sa Flipper Zero. Ako **pronađe signal u bazi podataka**, Flipper će automatski **znati koji uređaj je u pitanju** i omogućiće vam da interagujete sa njim.\
Ako ne pronađe, Flipper može **sačuvati** **signal** i omogućiti vam da ga **reprodukujete**.

## Reference

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristupiti **najnovijoj verziji PEASS ili preuzeti HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repozitorijum**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijum**](https://github.com/carlospolop/hacktricks-cloud).

</details>
