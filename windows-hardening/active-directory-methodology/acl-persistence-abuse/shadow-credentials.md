# Skadu-geloofsbriewe

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Inleiding <a href="#3f17" id="3f17"></a>

**Kyk na die oorspronklike pos vir [alle inligting oor hierdie tegniek](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

As 'n **opsomming**: as jy kan skryf na die **msDS-KeyCredentialLink** eienskap van 'n gebruiker/rekenaar, kan jy die **NT-hash van daardie objek** herwin.

In die pos word 'n metode uitgelê om **openbare-privaat sleutel-verifikasie-geloofsbriewe** op te stel om 'n unieke **Dienskaartjie** te bekom wat die teiken se NTLM-hash insluit. Hierdie proses behels die versleutelde NTLM_SUPPLEMENTAL_CREDENTIAL binne die Privilege Attribute Certificate (PAC), wat ontsluit kan word.

### Vereistes

Om hierdie tegniek toe te pas, moet sekere voorwaardes voldoen word:
- 'n Minimum van een Windows Server 2016-domeinbeheerder is nodig.
- Die domeinbeheerder moet 'n bedienerverifikasie digitale sertifikaat geïnstalleer hê.
- Die Aktiewe Gids moet op die Windows Server 2016-funksievlak wees.
- 'n Rekening met gedelegeerde regte om die msDS-KeyCredentialLink-eienskap van die teikenobjek te wysig, is nodig.

## Misbruik

Die misbruik van Sleutelvertroue vir rekenaarobjekte behels stappe wat verder gaan as die verkryging van 'n Ticket Granting Ticket (TGT) en die NTLM-hash. Die opsies sluit in:
1. Die skep van 'n **RC4 silwerkaartjie** om as bevoorregte gebruikers op die beoogde gasheer op te tree.
2. Die gebruik van die TGT met **S4U2Self** vir die nabootsing van **bevoorregte gebruikers**, wat wysigings aan die Dienskaartjie vereis om 'n diensklas by die diensnaam te voeg.

'n Belangrike voordeel van Sleutelvertroue-misbruik is dat dit beperk is tot die aanvaller se gegenereerde privaatsleutel, wat die delegasie na potensieel kwesbare rekeninge vermy en nie die skepping van 'n rekenaarrekening vereis nie, wat moeilik kan wees om te verwyder.

## Gereedskap

### [**Whisker**](https://github.com/eladshamir/Whisker)

Dit is gebaseer op DSInternals en bied 'n C#-koppelvlak vir hierdie aanval. Whisker en sy Python-teendeel, **pyWhisker**, maak manipulasie van die `msDS-KeyCredentialLink` eienskap moontlik om beheer oor Aktiewe Gids-rekeninge te verkry. Hierdie gereedskap ondersteun verskeie operasies soos byvoeging, lys, verwydering en skoonmaak van sleutelgelowiges van die teikenobjek.

**Whisker**-funksies sluit in:
- **Byvoeg**: Genereer 'n sleutelpaar en voeg 'n sleutelgelowige by.
- **Lys**: Vertoon alle sleutelgelowige inskrywings.
- **Verwyder**: Verwyder 'n gespesifiseerde sleutelgelowige.
- **Skoon**: Vee alle sleutelgelowiges uit, wat potensieel legitieme WHfB-gebruik kan ontwrig.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Dit brei Whisker funksionaliteit uit na **UNIX-gebaseerde stelsels**, deur gebruik te maak van Impacket en PyDSInternals vir omvattende uitbuitingsmoontlikhede, insluitend die lys, byvoeging en verwydering van KeyCredentials, sowel as die invoer en uitvoer daarvan in JSON-formaat.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray het as doel om **GenericWrite/GenericAll-toestemmings wat wydverspreide gebruikersgroepe mag hê oor domeinvoorwerpe** te benut om ShadowCredentials wyd toe te pas. Dit behels om in te teken op die domein, die funksionele vlak van die domein te verifieer, domeinvoorwerpe op te som, en te probeer om KeyCredentials by te voeg vir TGT-verwerwing en NT-hash-onthulling. Opruimingsopsies en herhalende benuttingstaktieke verbeter sy bruikbaarheid.


## Verwysings

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks-repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud-repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
