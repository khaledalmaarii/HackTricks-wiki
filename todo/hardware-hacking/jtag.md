# JTAG

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)je alat koji se može koristiti sa Raspberry PI ili Arduino uređajem kako bi se pronašli JTAG pinovi na nepoznatom čipu.\
Na **Arduino-u**, povežite **pinove od 2 do 11 sa 10 pinova koji potencijalno pripadaju JTAG-u**. Učitajte program na Arduino i on će pokušati da brute force-uje sve pinove kako bi pronašao da li neki od njih pripada JTAG-u i koji je svaki od njih.\
Na **Raspberry PI-ju** možete koristiti samo **pinove od 1 do 6** (6 pinova, pa ćete sporije testirati svaki potencijalni JTAG pin).

### Arduino

Na Arduino-u, nakon što povežete kablove (pinovi 2 do 11 sa JTAG pinovima i Arduino GND sa osnovnom GND), **učitajte JTAGenum program na Arduino** i u Serial Monitor pošaljite **`h`** (komanda za pomoć) i trebalo bi da vidite pomoć:

![](<../../.gitbook/assets/image (936).png>)

![](<../../.gitbook/assets/image (575).png>)

Konfigurišite **"Bez završetka linije" i 115200baud**.\
Pošaljite komandu s da započnete skeniranje:

![](<../../.gitbook/assets/image (771).png>)

Ako ste povezani sa JTAG-om, pronaći ćete jednu ili više **linija koje počinju sa FOUND!** koje ukazuju na pinove JTAG-a.
