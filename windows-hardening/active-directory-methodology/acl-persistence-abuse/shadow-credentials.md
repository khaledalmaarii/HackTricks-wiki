# Shadow Credentials

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

## Intro <a href="#3f17" id="3f17"></a>

**Check the original post for [all the information about this technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

As **summary**: as jy kan skryf na die **msDS-KeyCredentialLink** eienskap van 'n gebruiker/rekenaar, kan jy die **NT hash van daardie objek** verkry.

In die pos word 'n metode uiteengesit om **publieke-private sleutelverifikasie akrediteer** op te stel om 'n unieke **Service Ticket** te verkry wat die teiken se NTLM hash insluit. Hierdie proses behels die versleutelde NTLM_SUPPLEMENTAL_CREDENTIAL binne die Privilege Attribute Certificate (PAC), wat ontcijfer kan word.

### Requirements

Om hierdie tegniek toe te pas, moet sekere voorwaardes nagekom word:
- 'n Minimum van een Windows Server 2016 Domeinbeheerder is nodig.
- Die Domeinbeheerder moet 'n digitale sertifikaat vir bedienerverifikasie geïnstalleer hê.
- Die Active Directory moet op die Windows Server 2016 Funksionele Vlak wees.
- 'n Rekening met gedelegeerde regte om die msDS-KeyCredentialLink eienskap van die teiken objek te wysig is vereis.

## Abuse

Die misbruik van Key Trust vir rekenaarobjekte sluit stappe in wat verder gaan as die verkryging van 'n Ticket Granting Ticket (TGT) en die NTLM hash. Die opsies sluit in:
1. Die skep van 'n **RC4 silwer kaartjie** om as bevoorregte gebruikers op die beoogde gasheer op te tree.
2. Die gebruik van die TGT met **S4U2Self** vir die vervalsing van **bevoorregte gebruikers**, wat veranderinge aan die Service Ticket vereis om 'n diensklas by die diensnaam te voeg.

'n Beduidende voordeel van Key Trust misbruik is die beperking tot die aanvaller-gegenereerde private sleutel, wat delegasie aan potensieel kwesbare rekeninge vermy en nie die skepping van 'n rekenaarrekening vereis nie, wat moeilik kan wees om te verwyder.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Dit is gebaseer op DSInternals wat 'n C#-koppelvlak vir hierdie aanval bied. Whisker en sy Python teenhanger, **pyWhisker**, stel in staat om die `msDS-KeyCredentialLink` eienskap te manipuleer om beheer oor Active Directory rekeninge te verkry. Hierdie gereedskap ondersteun verskeie operasies soos om sleutelakrediete by te voeg, te lys, te verwyder en te skoon te maak van die teiken objek.

**Whisker** funksies sluit in:
- **Add**: Genereer 'n sleutel paar en voeg 'n sleutel akrediet by.
- **List**: Vertoon alle sleutel akrediet inskrywings.
- **Remove**: Verwyder 'n spesifieke sleutel akrediet.
- **Clear**: Verwyder alle sleutel akrediete, wat moontlik wettige WHfB gebruik kan ontwrig.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Dit brei Whisker se funksionaliteit uit na **UNIX-gebaseerde stelsels**, wat Impacket en PyDSInternals benut vir omvattende eksploitasiemogelijkheden, insluitend die lys, toevoeging en verwydering van KeyCredentials, sowel as die invoer en uitvoer daarvan in JSON-formaat.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray het ten doel om **Generiese Skryf/Generiese Alles toestemmings wat wye gebruikersgroepe oor domeinobjekte mag hê, te benut** om ShadowCredentials breedvoerig toe te pas. Dit behels om in die domein in te teken, die domein se funksionele vlak te verifieer, domeinobjekte te evalueer, en te probeer om KeyCredentials vir TGT verkryging en NT hash onthulling by te voeg. Skoonmaakopsies en rekursiewe uitbuitingstaktieke verbeter die nut daarvan.


## References

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
