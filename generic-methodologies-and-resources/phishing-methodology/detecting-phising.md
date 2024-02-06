# Detecção de Phishing

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para** os repositórios do [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introdução

Para detectar uma tentativa de phishing, é importante **entender as técnicas de phishing que estão sendo usadas atualmente**. Na página principal deste post, você pode encontrar essas informações, então se você não está ciente das técnicas que estão sendo usadas hoje, recomendo que vá para a página principal e leia pelo menos essa seção.

Este post é baseado na ideia de que os **atacantes tentarão de alguma forma imitar ou usar o nome de domínio da vítima**. Se seu domínio se chama `exemplo.com` e você for alvo de phishing usando um nome de domínio completamente diferente por algum motivo, como `vocêganhoualoteria.com`, essas técnicas não vão descobrir isso.

## Variações de nome de domínio

É **relativamente fácil** **descobrir** as tentativas de **phishing** que usarão um **nome de domínio semelhante** dentro do e-mail.\
É suficiente **gerar uma lista dos nomes de phishing mais prováveis** que um atacante pode usar e **verificar** se está **registrado** ou apenas verificar se há algum **IP** o utilizando.

### Encontrando domínios suspeitos

Para este propósito, você pode usar qualquer uma das seguintes ferramentas. Observe que essas ferramentas também realizarão solicitações DNS automaticamente para verificar se o domínio tem algum IP atribuído a ele:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

No mundo da computação, tudo é armazenado em bits (zeros e uns) na memória nos bastidores.\
Isso também se aplica aos domínios. Por exemplo, _windows.com_ se torna _01110111..._ na memória volátil do seu dispositivo de computação.\
No entanto, e se um desses bits for automaticamente alterado devido a uma explosão solar, raios cósmicos ou um erro de hardware? Ou seja, um dos 0's se torna um 1 e vice-versa.\
Aplicando esse conceito a solicitações DNS, é possível que o **domínio solicitado** que chega ao servidor DNS **não seja o mesmo que o domínio solicitado inicialmente**.

Por exemplo, uma modificação de 1 bit no domínio microsoft.com pode transformá-lo em _windnws.com._\
**Os atacantes podem registrar o maior número possível de domínios com bit-flipping relacionados à vítima para redirecionar usuários legítimos para sua infraestrutura**.

Para mais informações, leia [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

**Todos os possíveis nomes de domínio com bit-flipping também devem ser monitorados.**

### Verificações básicas

Depois de ter uma lista de potenciais nomes de domínio suspeitos, você deve **verificá-los** (principalmente as portas HTTP e HTTPS) para **verificar se estão usando algum formulário de login semelhante** a algum do domínio da vítima.\
Você também pode verificar a porta 3333 para ver se está aberta e executando uma instância do `gophish`.\
Também é interessante saber **há quanto tempo cada domínio suspeito foi descoberto**, quanto mais novo, mais arriscado é.\
Você também pode obter **capturas de tela** da página da web HTTP e/ou HTTPS suspeita para ver se é suspeita e, nesse caso, **acessá-la para dar uma olhada mais aprofundada**.

### Verificações avançadas

Se você quiser ir um passo adiante, recomendaria **monitorar esses domínios suspeitos e procurar por mais** de vez em quando (todos os dias? leva apenas alguns segundos/minutos). Você também deve **verificar** as **portas abertas** dos IPs relacionados e **procurar por instâncias de `gophish` ou ferramentas similares** (sim, os atacantes também cometem erros) e **monitorar as páginas da web HTTP e HTTPS dos domínios e subdomínios suspeitos** para ver se copiaram algum formulário de login das páginas da web da vítima.\
Para **automatizar isso**, recomendaria ter uma lista de formulários de login dos domínios da vítima, rastrear as páginas da web suspeitas e comparar cada formulário de login encontrado dentro dos domínios suspeitos com cada formulário de login do domínio da vítima usando algo como `ssdeep`.\
Se você localizou os formulários de login dos domínios suspeitos, você pode tentar **enviar credenciais falsas** e **verificar se está sendo redirecionado para o domínio da vítima**.

## Nomes de domínio usando palavras-chave

A página principal também menciona uma técnica de variação de nome de domínio que consiste em colocar o **nome de domínio da vítima dentro de um domínio maior** (por exemplo, paypal-financial.com para paypal.com).

### Transparência de Certificados

Não é possível adotar a abordagem anterior de "Força Bruta", mas na verdade é **possível descobrir tais tentativas de phishing** também graças à transparência de certificados. Sempre que um certificado é emitido por uma AC, os detalhes são tornados públicos. Isso significa que lendo a transparência do certificado ou mesmo monitorando-a, é **possível encontrar domínios que estão usando uma palavra-chave em seu nome**. Por exemplo, se um atacante gera um certificado de [https://paypal-financial.com](https://paypal-financial.com), ao ver o certificado é possível encontrar a palavra-chave "paypal" e saber que um e-mail suspeito está sendo usado.

O post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugere que você pode usar o Censys para pesquisar certificados que afetam uma palavra-chave específica e filtrar por data (apenas certificados "novos") e pelo emissor da AC "Let's Encrypt":

![](<../../.gitbook/assets/image (390).png>)

No entanto, você pode fazer "o mesmo" usando o site gratuito [**crt.sh**](https://crt.sh). Você pode **pesquisar pela palavra-chave** e **filtrar** os resultados **por data e AC** se desejar.

![](<../../.gitbook/assets/image (391).png>)

Usando essa última opção, você pode até usar o campo Identidades Correspondentes para ver se alguma identidade do domínio real corresponde a algum dos domínios suspeitos (observe que um domínio suspeito pode ser um falso positivo).

**Outra alternativa** é o fantástico projeto chamado [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream fornece um fluxo em tempo real de certificados recém-gerados que você pode usar para detectar palavras-chave especificadas em tempo (quase) real. Na verdade, existe um projeto chamado [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) que faz exatamente isso.

### **Novos domínios**

**Uma última alternativa** é reunir uma lista de **domínios recém-registrados** para alguns TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) fornece esse serviço) e **verificar as palavras-chave nesses domínios**. No entanto, os domínios longos geralmente usam um ou mais subdomínios, portanto a palavra-chave não aparecerá dentro do FLD e você não poderá encontrar o subdomínio de phishing.

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para** os repositórios do [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
