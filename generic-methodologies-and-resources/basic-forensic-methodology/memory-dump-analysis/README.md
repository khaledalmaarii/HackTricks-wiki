# Analiza memorije

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristupiti **najnovijoj verziji PEASS ili preuzeti HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks suvenir**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repozitorijum**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijum**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) je najrelevantniji događaj u oblasti kibernetičke bezbednosti u **Španiji** i jedan od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je ključno mesto susreta tehnoloških i bezbednosnih stručnjaka u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

## Početak

Počnite **tražiti** zlonamerne programe unutar pcap datoteke. Koristite **alate** navedene u [**Analizi zlonamernih programa**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility je glavni open-source okvir za analizu memorije**. Ovaj Python alat analizira dump-ove sa spoljnih izvora ili VMware VM-ova, identifikujući podatke poput procesa i lozinki na osnovu profila OS dump-a. Proširiv je pomoću dodataka, što ga čini veoma fleksibilnim za forenzičke istrage.

[**Pronađite ovde cheatsheet**](volatility-cheatsheet.md)

## Izveštaj o padu mini dump-a

Kada je dump mali (samo nekoliko KB, možda nekoliko MB) tada je verovatno izveštaj o padu mini dump-a, a ne dump memorije.

![](<../../../.gitbook/assets/image (532).png>)

Ako imate instaliran Visual Studio, možete otvoriti ovu datoteku i dobiti osnovne informacije poput imena procesa, arhitekture, informacija o izuzecima i izvršenih modula:

![](<../../../.gitbook/assets/image (263).png>)

Takođe možete učitati izuzetak i videti dekompilirane instrukcije

![](<../../../.gitbook/assets/image (142).png>)

![](<../../../.gitbook/assets/image (610).png>)

U svakom slučaju, Visual Studio nije najbolji alat za obavljanje analize dubine dump-a.

Trebalo bi ga **otvoriti** koristeći **IDA** ili **Radare** kako biste ga detaljno pregledali.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) je najrelevantniji događaj u oblasti kibernetičke bezbednosti u **Španiji** i jedan od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je ključno mesto susreta tehnoloških i bezbednosnih stručnjaka u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristupiti **najnovijoj verziji PEASS ili preuzeti HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks suvenir**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repozitorijum**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijum**](https://github.com/carlospolop/hacktricks-cloud).

</details>
