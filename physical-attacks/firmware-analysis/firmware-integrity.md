{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Integritet firmvera

**Prilagođena firmvera i/ili kompajlirani binarni fajlovi mogu biti otpremljeni kako bi se iskoristile greške u integritetu ili verifikaciji potpisa**. Sledeći koraci se mogu pratiti za kompajlaciju backdoor bind shell-a:

1. Firmvera se može ekstrahovati koristeći firmware-mod-kit (FMK).
2. Treba identifikovati arhitekturu firmvera i endijnost.
3. Može se izgraditi cross compiler koristeći Buildroot ili druge odgovarajuće metode za okruženje.
4. Backdoor se može izgraditi koristeći cross compiler.
5. Backdoor se može kopirati u /usr/bin direktorijum ekstrahovane firmvere.
6. Odgovarajući QEMU binarni fajl može se kopirati u rootfs ekstrahovane firmvere.
7. Backdoor se može emulirati koristeći chroot i QEMU.
8. Backdoor se može pristupiti putem netcat-a.
9. QEMU binarni fajl treba biti uklonjen iz rootfs ekstrahovane firmvere.
10. Izmenjena firmvera može biti ponovo upakovana koristeći FMK.
11. Backdoored firmvera može biti testirana emulacijom sa alatom za analizu firmvera (FAT) i povezivanjem na IP adresu i port ciljanog backdoor-a koristeći netcat.

Ako je već dobijena root shell putem dinamičke analize, manipulacije bootloader-om ili testiranja hardverske sigurnosti, mogu se izvršiti prethodno kompajlirani zlonamerni binarni fajlovi kao što su implanti ili reverzni shell-ovi. Automatizovani alati za payload/implant kao što je Metasploit framework i 'msfvenom' mogu se iskoristiti sledećim koracima:

1. Treba identifikovati arhitekturu firmvera i endijnost.
2. Msfvenom se može koristiti za specificiranje ciljnog payload-a, IP adrese napadača, broja port-a za slušanje, tipa fajla, arhitekture, platforme i izlaznog fajla.
3. Payload se može preneti na kompromitovani uređaj i osigurati da ima dozvole za izvršavanje.
4. Metasploit se može pripremiti za obradu dolaznih zahteva pokretanjem msfconsole-a i konfigurisanjem postavki prema payload-u.
5. Meterpreter reverzni shell može se izvršiti na kompromitovanom uređaju.
6. Meterpreter sesije se mogu pratiti dok se otvaraju.
7. Post-exploitation aktivnosti se mogu izvesti.

Ako je moguće, ranjivosti unutar startup skripti mogu se iskoristiti za dobijanje trajnog pristupa uređaju tokom ponovnog pokretanja. Ove ranjivosti se javljaju kada startup skripte referenciraju, [simbolički povezuju](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), ili zavise od koda smeštenog na nepouzdanim montiranim lokacijama kao što su SD kartice i flash volumeni korišćeni za skladištenje podataka van root fajl sistema.

## Reference
* Za više informacija pogledajte [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
