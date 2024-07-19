# Analiza memorijskih dump-ova

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) je najrelevantnija sajber bezbednosna manifestacija u **Španiji** i jedna od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je vrelo mesto okupljanja za profesionalce u tehnologiji i sajber bezbednosti u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

## Početak

Počnite **pretragu** za **malverom** unutar pcap-a. Koristite **alate** navedene u [**Analiza malvera**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility je glavni open-source okvir za analizu memorijskih dump-ova**. Ovaj Python alat analizira dump-ove iz spoljašnjih izvora ili VMware VM-ova, identifikujući podatke kao što su procesi i lozinke na osnovu OS profila dump-a. Proširiv je sa plugin-ovima, što ga čini veoma svestranim za forenzičke istrage.

**[Ovde pronađite cheatsheet](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## Izveštaj o mini dump-u

Kada je dump mali (samo nekoliko KB, možda nekoliko MB), onda je verovatno reč o izveštaju o mini dump-u, a ne o memorijskom dump-u.

![](<../../../.gitbook/assets/image (216).png>)

Ako imate instaliran Visual Studio, možete otvoriti ovu datoteku i povezati neke osnovne informacije kao što su ime procesa, arhitektura, informacije o izuzecima i moduli koji se izvršavaju:

![](<../../../.gitbook/assets/image (217).png>)

Takođe možete učitati izuzetak i videti dekompilovane instrukcije

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

U svakom slučaju, Visual Studio nije najbolji alat za izvođenje analize dubine dump-a.

Trebalo bi da ga **otvorite** koristeći **IDA** ili **Radare** za detaljnu inspekciju.
