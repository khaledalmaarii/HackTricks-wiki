# PsExec/Winexec/ScExec

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Hoe werk hulle

Die proses word uitgelig in die volgende stappe, wat illustreer hoe diensbinêre lêers gemanipuleer word om afstandsbediening op 'n teikermasjien te bereik via SMB:

1. **Kopiëring van 'n diensbinêre lêer na die ADMIN$-deel via SMB** word uitgevoer.
2. **Skepping van 'n diens op die afstandsbediende masjien** word gedoen deur na die binêre lêer te verwys.
3. Die diens word **afstandsbedien** gestart.
4. By afsluiting word die diens **gestop en die binêre lêer uitgevee**.

### **Proses van Handmatige Uitvoering van PsExec**

Assumeer dat daar 'n uitvoerbare lading is (geskep met msfvenom en geobfuskeer met behulp van Veil om antivirusopsporing te ontduik), genaamd 'met8888.exe', wat 'n meterpreter reverse_http-lading verteenwoordig. Die volgende stappe word geneem:

- **Kopiëring van die binêre lêer**: Die uitvoerbare lêer word vanaf 'n opdragpunt na die ADMIN$-deel gekopieer, alhoewel dit enige plek op die lêersisteem geplaas kan word om verborge te bly.

- **Skepping van 'n diens**: Deur die Windows `sc`-opdrag te gebruik, wat die ondervraging, skepping en verwydering van Windows-diens op afstand moontlik maak, word 'n diens met die naam "meterpreter" geskep om na die opgelaaide binêre lêer te verwys.

- **Die diens begin**: Die finale stap behels die begin van die diens, wat waarskynlik sal lei tot 'n "tyduit" -fout as gevolg van die binêre lêer wat nie 'n egte diensbinêre lêer is nie en nie die verwagte responskode teruggee nie. Hierdie fout is onbelangrik omdat die primêre doel die uitvoering van die binêre lêer is.

Waarneming van die Metasploit-luisteraar sal aandui dat die sessie suksesvol geïnisieer is.

[Leer meer oor die `sc`-opdrag](https://technet.microsoft.com/en-us/library/bb490995.aspx).


Vind meer gedetailleerde stappe in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Jy kan ook die Windows Sysinternals-binêre lêer PsExec.exe gebruik:**

![](<../../.gitbook/assets/image (165).png>)

Jy kan ook [**SharpLateral**](https://github.com/mertdas/SharpLateral) gebruik:

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
