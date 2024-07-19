{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Firmware Integriteit

Die **aangepaste firmware en/of gecompileerde binêre kan opgelaai word om integriteit of handtekening verifikasiefoute te benut**. Die volgende stappe kan gevolg word vir backdoor bind shell compilering:

1. Die firmware kan onttrek word met firmware-mod-kit (FMK).
2. Die teiken firmware argitektuur en endianness moet geïdentifiseer word.
3. 'n Kruiskompiler kan gebou word met behulp van Buildroot of ander geskikte metodes vir die omgewing.
4. Die backdoor kan gebou word met die kruiskompiler.
5. Die backdoor kan na die onttrokken firmware /usr/bin gids gekopieer word.
6. Die toepaslike QEMU binêre kan na die onttrokken firmware rootfs gekopieer word.
7. Die backdoor kan geëmuleer word met behulp van chroot en QEMU.
8. Die backdoor kan via netcat toeganklik gemaak word.
9. Die QEMU binêre moet van die onttrokken firmware rootfs verwyder word.
10. Die gewysigde firmware kan herverpak word met behulp van FMK.
11. Die backdoored firmware kan getoets word deur dit te emuleer met firmware analise toolkit (FAT) en verbinding te maak met die teiken backdoor IP en poort met behulp van netcat.

As 'n root shell reeds verkry is deur dinamiese analise, bootloader manipulasie, of hardeware sekuriteitstoetsing, kan voorafgecompileerde kwaadwillige binêre soos implante of omgekeerde shells uitgevoer word. Geoutomatiseerde payload/implant gereedskap soos die Metasploit raamwerk en 'msfvenom' kan benut word met die volgende stappe:

1. Die teiken firmware argitektuur en endianness moet geïdentifiseer word.
2. Msfvenom kan gebruik word om die teiken payload, aanvaller gasheer IP, luister poortnommer, lêertipe, argitektuur, platform, en die uitvoer lêer spesifiek aan te dui.
3. Die payload kan na die gecompromitteerde toestel oorgedra word en verseker word dat dit uitvoeringsregte het.
4. Metasploit kan voorberei word om inkomende versoeke te hanteer deur msfconsole te begin en die instellings volgens die payload te konfigureer.
5. Die meterpreter omgekeerde shell kan op die gecompromitteerde toestel uitgevoer word.
6. Meterpreter sessies kan gemonitor word soos hulle oopmaak.
7. Post-exploitatie aktiwiteite kan uitgevoer word.

As dit moontlik is, kan kwesbaarhede binne opstart skripte benut word om volgehoue toegang tot 'n toestel oor herlaai te verkry. Hierdie kwesbaarhede ontstaan wanneer opstart skripte verwys, [simbolies skakel](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), of afhanklik is van kode wat geleë is in onbetroubare gemonteerde plekke soos SD kaarte en flits volumes wat gebruik word om data buite wortel lêersisteme te stoor.

## Verwysings
* Vir verdere inligting kyk [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
