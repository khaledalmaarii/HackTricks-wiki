## Integritet firmvera

**Prilagođeni firmver i/ili kompajlirani binarni fajlovi mogu biti otpremljeni kako bi se iskoristile greške u integritetu ili verifikaciji potpisa**. Sledeći koraci se mogu pratiti za kompajlaciju backdoor bind shell-a:

1. Firmver se može ekstrahovati koristeći firmware-mod-kit (FMK).
2. Treba identifikovati arhitekturu firmvera i endijnost.
3. Može se izgraditi cross compiler koristeći Buildroot ili druge odgovarajuće metode za okruženje.
4. Backdoor se može izgraditi koristeći cross compiler.
5. Backdoor se može kopirati u /usr/bin direktorijum ekstrahovanog firmvera.
6. Odgovarajući QEMU binarni fajl može se kopirati u rootfs ekstrahovanog firmvera.
7. Backdoor se može emulirati koristeći chroot i QEMU.
8. Backdoor se može pristupiti putem netcat-a.
9. QEMU binarni fajl treba ukloniti iz rootfs ekstrahovanog firmvera.
10. Izmenjeni firmver se može ponovo pakovati koristeći FMK.
11. Backdoored firmver se može testirati emulacijom sa alatom za analizu firmvera (FAT) i povezivanjem na IP adresu i port ciljanog backdoora koristeći netcat.

Ako je već dobijena root shell putem dinamičke analize, manipulacije bootloader-om ili testiranja hardverske sigurnosti, prekompajlirani zlonamerni binarni fajlovi kao što su implanti ili reverzni shell-ovi mogu se izvršiti. Automatizovani alati za payload/implant, kao što je Metasploit framework i 'msfvenom', mogu se iskoristiti sledećim koracima:

1. Treba identifikovati arhitekturu firmvera i endijnost.
2. Msfvenom se može koristiti za specificiranje ciljanog payload-a, IP adrese napadača, broja slušajućeg porta, tipa fajla, arhitekture, platforme i izlaznog fajla.
3. Payload se može preneti na kompromitovani uređaj i osigurati da ima dozvole za izvršavanje.
4. Metasploit se može pripremiti za obradu dolaznih zahteva pokretanjem msfconsole-a i konfigurisanjem postavki prema payload-u.
5. Meterpreter reverzni shell se može izvršiti na kompromitovanom uređaju.
