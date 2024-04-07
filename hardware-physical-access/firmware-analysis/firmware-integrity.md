<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Integritet Firmware-a

**Prilagođeni firmware i/ili kompajlirane binarne datoteke mogu biti otpremljene kako bi se iskoristile slabosti u proveri integriteta ili potpisa**. Sledeći koraci mogu biti praćeni za kompilaciju backdoor bind shell-a:

1. Firmware se može izdvojiti korišćenjem firmware-mod-kit (FMK).
2. Treba identifikovati arhitekturu i endianess ciljnog firmware-a.
3. Može se izgraditi prelazni kompajler korišćenjem Buildroot-a ili drugih odgovarajućih metoda za okruženje.
4. Backdoor se može izgraditi korišćenjem prelaznog kompajlera.
5. Backdoor se može kopirati u izdvojeni firmware /usr/bin direktorijum.
6. Odgovarajući QEMU binarni fajl se može kopirati u izdvojeni firmware rootfs.
7. Backdoor se može emulirati korišćenjem chroot-a i QEMU-a.
8. Backdoor se može pristupiti putem netcat-a.
9. QEMU binarni fajl treba ukloniti iz izdvojenog firmware rootfs-a.
10. Modifikovani firmware se može ponovo zapakovati korišćenjem FMK.
11. Backdoored firmware se može testirati emuliranjem sa firmware analitičkim alatom (FAT) i povezivanjem na ciljni backdoor IP i port korišćenjem netcat-a.

Ako je već dobijena root shell kroz dinamičku analizu, manipulaciju bootloader-a ili testiranje sigurnosti hardvera, prekompajlirane zlonamerne binarne datoteke poput implanta ili reverznih shell-ova mogu se izvršiti. Automatizovani alati za payload/implant kao što je Metasploit okvir i 'msfvenom' mogu se iskoristiti sledećim koracima:

1. Treba identifikovati arhitekturu i endianess ciljnog firmware-a.
2. Msfvenom se može koristiti za specificiranje ciljnog payload-a, IP adrese napadača, broja slušanja porta, tipa fajla, arhitekture, platforme i izlaznog fajla.
3. Payload se može preneti na kompromitovani uređaj i osigurati da ima dozvole za izvršavanje.
4. Metasploit se može pripremiti za obradu dolaznih zahteva pokretanjem msfconsole-a i konfigurisanjem podešavanja prema payload-u.
5. Meterpreter reverzni shell se može izvršiti na kompromitovanom uređaju.
6. Meterpreter sesije se mogu pratiti dok se otvaraju.
7. Mogu se izvršiti post-eksploatacijske aktivnosti.

Ako je moguće, ranjivosti unutar startup skripti mogu se iskoristiti kako bi se stekao trajni pristup uređaju tokom ponovnih pokretanja. Ove ranjivosti se javljaju kada startup skripte referišu, [simbolički linkuju](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), ili zavise od koda smeštenog na nepoverenim montiranim lokacijama poput SD kartica i fleš volumena korišćenih za skladištenje podataka van korenskih fajl sistema.

## Reference
* Za više informacija pogledajte [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
