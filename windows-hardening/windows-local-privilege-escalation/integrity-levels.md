<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>


# Integriteitsvlakke

In Windows Vista en latere weergawes het alle beskermde items 'n **integriteitsvlak-etiket**. Hierdie opset ken meestal 'n "medium" integriteitsvlak toe aan lêers en registerleidrade, behalwe vir sekere lêers en lêers waarop Internet Explorer 7 teen 'n lae integriteitsvlak kan skryf. Die verstekgedrag is dat prosesse wat deur standaardgebruikers geïnisieer word, 'n medium integriteitsvlak het, terwyl dienste gewoonlik op 'n stelselintegriteitsvlak werk. 'n Hoë-integriteitsmerk beskerm die hoofgids.

'n Belangrike reël is dat voorwerpe nie deur prosesse met 'n laer integriteitsvlak as die voorwerp se vlak gewysig kan word nie. Die integriteitsvlakke is as volg:

- **Onbetroubaar**: Hierdie vlak is vir prosesse met anonieme aanmeldings. %%%Voorbeeld: Chrome%%%
- **Laag**: Hoofsaaklik vir internetinteraksies, veral in Internet Explorer se Beskermde Modus, wat geassosieerde lêers en prosesse en sekere lêers soos die **Tydelike Internet-lêer** beïnvloed. Prosesse met 'n lae integriteit het aansienlike beperkings, insluitend geen register skryftoegang en beperkte gebruikersprofiel skryftoegang.
- **Medium**: Die verstekvlak vir die meeste aktiwiteite, toegewys aan standaardgebruikers en voorwerpe sonder spesifieke integriteitsvlakke. Selfs lede van die Administrateursgroep werk standaard op hierdie vlak.
- **Hoog**: Gereserveer vir administrateurs, wat hulle in staat stel om voorwerpe op laer integriteitsvlakke, insluitend die op die hoë vlak self, te wysig.
- **Stelsel**: Die hoogste operasionele vlak vir die Windows-kernel en kerndienste, buite bereik selfs vir administrateurs, wat versekering bied vir die beskerming van noodsaaklike stelselfunksies.
- **Installer**: 'n Unieke vlak wat bo alle ander staan, wat voorwerpe op hierdie vlak in staat stel om enige ander voorwerp te deïnstalleer.

Jy kan die integriteitsvlak van 'n proses kry deur **Process Explorer** van **Sysinternals** te gebruik, deur die **eienskappe** van die proses te ontsluit en die "**Sekuriteit**" -tabblad te besigtig:

![](<../../.gitbook/assets/image (318).png>)

Jy kan ook jou **huidige integriteitsvlak** kry deur `whoami /groups` te gebruik

![](<../../.gitbook/assets/image (319).png>)

## Integriteitsvlakke in lêersisteem

'n Voorwerp binne die lêersisteem mag 'n **minimum integriteitsvlakvereiste** hê, en as 'n proses nie hierdie integriteitsproses het nie, sal dit nie daarmee kan interaksie hê nie.\
Byvoorbeeld, laat ons 'n **gewone lêer vanuit 'n gewone gebruikerskonsole skep en die regte nagaan**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Nou, laat ons 'n minimum integriteitsvlak van **Hoog** aan die lêer toeken. Dit **moet gedoen word vanuit 'n konsole** wat as **administrateur** uitgevoer word, aangesien 'n **gewone konsole** in 'n Medium Integriteitsvlak uitgevoer word en **nie toegelaat sal word** om 'n Hoë Integriteitsvlak aan 'n objek toe te ken nie:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
Hier is waar dinge interessant raak. Jy kan sien dat die gebruiker `DESKTOP-IDJHTKP\user` **VOLLE voorregte** oor die lêer het (inderdaad, hierdie was die gebruiker wat die lêer geskep het), maar as gevolg van die minimum integriteitsvlak wat geïmplementeer is, sal hy nie die lêer kan wysig nie tensy hy binne 'n Hoë Integriteitsvlak hardloop nie (let daarop dat hy dit steeds kan lees):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Daarom, as 'n lêer 'n minimum integriteitsvlak het, moet jy ten minste op daardie integriteitsvlak loop om dit te wysig.**
{% endhint %}

## Integriteitsvlakke in Binêre lêers

Ek het 'n kopie van `cmd.exe` gemaak in `C:\Windows\System32\cmd-laag.exe` en dit 'n **integriteitsvlak van laag vanuit 'n administrateurkonsol** gegee:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Nou, wanneer ek `cmd-low.exe` uitvoer, sal dit **onder 'n lae-integriteitsvlak** loop in plaas van 'n medium een:

![](<../../.gitbook/assets/image (320).png>)

Vir nuuskierige mense, as jy 'n hoë integriteitsvlak toewys aan 'n binêre lêer (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), sal dit nie outomaties met 'n hoë integriteitsvlak loop nie (as jy dit vanaf 'n medium integriteitsvlak aanroep - standaard - sal dit onder 'n medium integriteitsvlak loop).

## Integriteitsvlakke in Prosesse

Nie alle lêers en vouers het 'n minimum integriteitsvlak nie, **maar alle prosesse loop onder 'n integriteitsvlak**. En soos met die lêerstelsel, **as 'n proses binne 'n ander proses wil skryf, moet dit ten minste dieselfde integriteitsvlak hê**. Dit beteken dat 'n proses met 'n lae integriteitsvlak nie 'n handvatsel met volle toegang tot 'n proses met 'n medium integriteitsvlak kan oopmaak nie.

As gevolg van die beperkings wat in hierdie en die vorige afdeling genoem is, word dit altyd vanuit 'n veiligheidsoogpunt **aanbeveel om 'n proses in die laagste moontlike integriteitsvlak uit te voer**.


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
