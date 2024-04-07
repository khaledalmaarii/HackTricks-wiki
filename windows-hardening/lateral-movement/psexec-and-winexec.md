# PsExec/Winexec/ScExec

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Hoe werk hulle

Die proses word uitgelig in die volgende stappe, wat illustreer hoe diens-binêre lêers gemanipuleer word om afgeleë uitvoering op 'n teikengreepmasjien via SMB te bereik:

1. **Kopiëring van 'n diens-binêre lêer na die ADMIN$-aandeel oor SMB** word uitgevoer.
2. **Skepping van 'n diens op die afgeleë masjien** word gedoen deur na die binêre lêer te verwys.
3. Die diens word **afgeleë gestart**.
4. By afsluiting word die diens **gestop, en die binêre lêer word verwyder**.

### **Proses van Handmatige Uitvoering van PsExec**

As daar 'n uitvoerbare lading is (geskep met msfvenom en geobfuskeer met Veil om antivirusopsporing te ontduik), genaamd 'met8888.exe', wat 'n meterpreter reverse\_http-lading voorstel, word die volgende stappe geneem:

* **Kopiëring van die binêre lêer**: Die uitvoerbare lêer word vanaf 'n opdragpunt na die ADMIN$-aandeel gekopieer, alhoewel dit enige plek op die lêersisteem geplaas kan word om verborge te bly.
* **Skepping van 'n diens**: Deur die Windows `sc`-opdrag te gebruik, wat toelaat vir die ondervraging, skepping, en verwydering van Windows-dienste op afstand, word 'n diens genaamd "meterpreter" geskep om na die opgelaaide binêre lêer te verwys.
* **Begin van die diens**: Die finale stap behels die begin van die diens, wat waarskynlik 'n "tyduit" fout sal veroorsaak weens die binêre lêer wat nie 'n ware diens-binêre lêer is nie en nie die verwagte responskode teruggee nie. Hierdie fout is onbelangrik aangesien die primêre doel die uitvoering van die binêre lêer is.

Waarneming van die Metasploit-luisteraar sal aandui dat die sessie suksesvol geïnisieer is.

[Leer meer oor die `sc`-opdrag](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Vind meer gedetailleerde stappe in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Jy kan ook die Windows Sysinternals-binêre PsExec.exe gebruik:**

![](<../../.gitbook/assets/image (925).png>)

Jy kan ook [**SharpLateral**](https://github.com/mertdas/SharpLateral) gebruik:

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
