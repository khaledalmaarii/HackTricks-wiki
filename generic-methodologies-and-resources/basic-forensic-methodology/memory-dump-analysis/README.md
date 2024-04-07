# Analiza ispucavanja memorije

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristupiti **najnovijoj verziji PEASS ili preuzeti HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks suvenir**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova** na [**hacktricks repozitorijum**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijum**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) je najrelevantniji događaj u oblasti kibernetičke bezbednosti u **Španiji** i jedan od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je ključno mesto susreta tehnoloških i bezbednosnih stručnjaka u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

## Početak

Počnite **tražiti** **malver** unutar pcap datoteke. Koristite **alate** navedene u [**Analizi Malvera**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility je glavni open-source okvir za analizu ispucavanja memorije**. Ovaj Python alat analizira ispucavanja iz eksternih izvora ili VMware VM-ova, identifikujući podatke poput procesa i lozinki na osnovu profila OS ispucavanja. Proširiv je pomoću dodataka, što ga čini veoma fleksibilnim za forenzička istraživanja.

[**Pronađite ovde cheatsheet**](volatility-cheatsheet.md)

## Izveštaj o padu mini ispucavanja

Kada je ispucavanje malo (samo nekoliko KB, možda nekoliko MB) tada je verovatno izveštaj o padu mini ispucavanja, a ne ispucavanje memorije.

![](<../../../.gitbook/assets/image (529).png>)

Ako imate instaliran Visual Studio, možete otvoriti ovu datoteku i vezati neke osnovne informacije poput imena procesa, arhitekture, informacija o izuzetku i modula koji se izvršavaju:

![](<../../../.gitbook/assets/image (260).png>)

Takođe možete učitati izuzetak i videti dekompilirane instrukcije

![](<../../../.gitbook/assets/image (139).png>)

![](<../../../.gitbook/assets/image (607).png>)

U svakom slučaju, Visual Studio nije najbolji alat za obavljanje analize dubine ispucavanja.

Treba ga **otvoriti** koristeći **IDA** ili **Radare** kako bi se detaljno pregledao.

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
* **Podelite svoje hakovanje trikove slanjem PR-ova** na [**hacktricks repozitorijum**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijum**](https://github.com/carlospolop/hacktricks-cloud).

</details>
