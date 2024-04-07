# PsExec/Winexec/ScExec

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Kako funkcionišu

Proces je opisan u koracima ispod, ilustrujući kako se binarni fajlovi servisa manipulišu kako bi se postiglo udaljeno izvršavanje na ciljnoj mašini putem SMB-a:

1. **Kopiranje binarnog fajla servisa na ADMIN$ deljenje preko SMB-a** se vrši.
2. **Kreiranje servisa na udaljenoj mašini** se obavlja usmeravanjem ka binarnom fajlu.
3. Servis se **pokreće udaljeno**.
4. Po završetku, servis se **zaustavlja, a binarni fajl se briše**.

### **Proces Ručnog Izvršavanja PsExec-a**

Pretpostavljajući da postoji izvršni payload (kreiran sa msfvenom i obfuskovan korišćenjem Veil-a kako bi izbegao detekciju antivirusa), nazvan 'met8888.exe', koji predstavlja meterpreter reverse\_http payload, sledeći koraci se preduzimaju:

* **Kopiranje binarnog fajla**: Izvršni fajl se kopira na ADMIN$ deljenje iz komandne linije, iako može biti smešten bilo gde na fajl sistemu kako bi ostao sakriven.
* **Kreiranje servisa**: Korišćenjem Windows `sc` komande, koja omogućava upitivanje, kreiranje i brisanje Windows servisa udaljeno, kreiran je servis nazvan "meterpreter" koji pokazuje na uploadovani binarni fajl.
* **Pokretanje servisa**: Poslednji korak uključuje pokretanje servisa, što će verovatno rezultirati "time-out" greškom zbog toga što binarni fajl nije pravi binarni fajl servisa i ne vraća očekivani kod odgovora. Ova greška nije bitna jer je primarni cilj izvršavanje binarnog fajla.

Posmatranjem Metasploit slušaoca otkriće se da je sesija uspešno pokrenuta.

[Saznajte više o `sc` komandi](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Pronađite detaljnije korake na: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Takođe možete koristiti Windows Sysinternals binarni PsExec.exe:**

![](<../../.gitbook/assets/image (925).png>)

Možete takođe koristiti [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
