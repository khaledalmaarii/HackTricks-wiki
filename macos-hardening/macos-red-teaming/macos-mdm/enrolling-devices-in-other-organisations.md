# Inscrição de Dispositivos em Outras Organizações

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Introdução

Como [**comentado anteriormente**](./#what-is-mdm-mobile-device-management)**,** para tentar inscrever um dispositivo em uma organização **apenas é necessário um Número de Série pertencente a essa Organização**. Uma vez que o dispositivo é inscrito, várias organizações instalarão dados sensíveis no novo dispositivo: certificados, aplicativos, senhas de WiFi, configurações de VPN [e assim por diante](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Portanto, este poderia ser um ponto de entrada perigoso para atacantes se o processo de inscrição não estiver corretamente protegido.

**O seguinte é um resumo da pesquisa [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consulte para mais detalhes técnicos!**

## Visão Geral da Análise Binária DEP e MDM

Esta pesquisa explora as binárias associadas ao Programa de Inscrição de Dispositivos (DEP) e ao Gerenciamento de Dispositivos Móveis (MDM) no macOS. Os componentes-chave incluem:

- **`mdmclient`**: Comunica-se com servidores MDM e aciona verificações DEP em versões do macOS anteriores a 10.13.4.
- **`profiles`**: Gerencia Perfis de Configuração e aciona verificações DEP em versões do macOS 10.13.4 e posteriores.
- **`cloudconfigurationd`**: Gerencia comunicações de API DEP e recupera perfis de Inscrição de Dispositivos.

As verificações DEP utilizam as funções `CPFetchActivationRecord` e `CPGetActivationRecord` do framework privado de Perfis de Configuração para buscar o Registro de Ativação, com `CPFetchActivationRecord` coordenando com `cloudconfigurationd` através de XPC.

## Engenharia Reversa do Protocolo Tesla e do Esquema Absinthe

A verificação DEP envolve o `cloudconfigurationd` enviando um payload JSON criptografado e assinado para _iprofiles.apple.com/macProfile_. O payload inclui o número de série do dispositivo e a ação "RequestProfileConfiguration". O esquema de criptografia usado é referido internamente como "Absinthe". Desvendar este esquema é complexo e envolve numerosas etapas, o que levou à exploração de métodos alternativos para inserir números de série arbitrários na solicitação de Registro de Ativação.

## Interceptação de Solicitações DEP

Tentativas de interceptar e modificar solicitações DEP para _iprofiles.apple.com_ usando ferramentas como Charles Proxy foram dificultadas pela criptografia do payload e medidas de segurança SSL/TLS. No entanto, habilitar a configuração `MCCloudConfigAcceptAnyHTTPSCertificate` permite ignorar a validação do certificado do servidor, embora a natureza criptografada do payload ainda impeça a modificação do número de série sem a chave de descriptografia.

## Instrumentando Binários do Sistema Interagindo com DEP

Instrumentar binários do sistema como `cloudconfigurationd` requer desabilitar a Proteção de Integridade do Sistema (SIP) no macOS. Com o SIP desabilitado, ferramentas como LLDB podem ser usadas para se conectar a processos do sistema e potencialmente modificar o número de série usado nas interações da API DEP. Este método é preferível, pois evita as complexidades de autorizações e assinatura de código.

**Explorando a Instrumentação Binária:**
Modificar o payload da solicitação DEP antes da serialização JSON em `cloudconfigurationd` provou ser eficaz. O processo envolveu:

1. Conectar o LLDB ao `cloudconfigurationd`.
2. Localizar o ponto onde o número de série do sistema é buscado.
3. Injetar um número de série arbitrário na memória antes que o payload seja criptografado e enviado.

Este método permitiu recuperar perfis DEP completos para números de série arbitrários, demonstrando uma vulnerabilidade potencial.

### Automatizando a Instrumentação com Python

O processo de exploração foi automatizado usando Python com a API LLDB, tornando possível injetar programaticamente números de série arbitrários e recuperar perfis DEP correspondentes.

### Impactos Potenciais das Vulnerabilidades DEP e MDM

A pesquisa destacou preocupações significativas de segurança:

1. **Divulgação de Informações**: Ao fornecer um número de série registrado no DEP, informações organizacionais sensíveis contidas no perfil DEP podem ser recuperadas.
2. **Inscrição DEP Fraudulenta**: Sem autenticação adequada, um atacante com um número de série registrado no DEP pode inscrever um dispositivo fraudulento no servidor MDM de uma organização, potencialmente obtendo acesso a dados sensíveis e recursos de rede.

Em conclusão, enquanto o DEP e o MDM fornecem ferramentas poderosas para gerenciar dispositivos Apple em ambientes corporativos, também apresentam vetores de ataque potenciais que precisam ser protegidos e monitorados.
