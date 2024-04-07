# Geheue dump-analise

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy by 'n **cybersekerheidsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-klere**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekerheidgebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en sibersekerheidsprofessionals in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

## Begin

Begin met **soek** vir **malware** binne die pcap. Gebruik die **gereedskap** wat genoem word in [**Malware-analise**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility is die belangrikste oopbronraamwerk vir geheue dump-analise**. Hierdie Python-gereedskap analiseer damps van eksterne bronne of VMware VM's, identifiseer data soos prosesse en wagwoorde gebaseer op die OS-profiel van die dump. Dit is uitbreibaar met bykomstighede, wat dit baie veelsydig maak vir forensiese ondersoeke.

[**Vind hier 'n spiekbrief**](volatility-cheatsheet.md)

## Mini dump-kraakverslag

Wanneer die dump klein is (net 'n paar KB, miskien 'n paar MB) is dit waarskynlik 'n mini dump-kraakverslag en nie 'n geheue dump nie.

![](<../../../.gitbook/assets/image (529).png>)

As jy Visual Studio geïnstalleer het, kan jy hierdie lêer oopmaak en 'n paar basiese inligting soos prosesnaam, argitektuur, uitsonderingsinligting en modules wat uitgevoer word, bind:

![](<../../../.gitbook/assets/image (260).png>)

Jy kan ook die uitsondering laai en die gedekomponeerde instruksies sien

![](<../../../.gitbook/assets/image (139).png>)

![](<../../../.gitbook/assets/image (607).png>)

Hoe dan ook, Visual Studio is nie die beste gereedskap om 'n analise van die diepte van die dump uit te voer nie.

Jy moet dit **open** met **IDA** of **Radare** om dit in **diepte** te ondersoek.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekerheidgebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en sibersekerheidsprofessionals in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy by 'n **cybersekerheidsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-klere**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>
