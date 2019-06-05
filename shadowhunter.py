#!/usr/bin/env python
import os
import subprocess
import binascii

def get_binfmt_dir():
    mount = []
    with open("/proc/mounts") as m:
        mounts = m.read().split("\n")

    binfmt_path = [x.split(" ")[1] for x in mounts if x.startswith("binfmt")]
    if len(binfmt_path) == 0:
        raise "binfmt_path not mounted on this system..."

    return binfmt_path[0]

def get_suid_binaries():
    print "[+] Getting list of suid binaries..."
    FNULL = open(os.devnull, 'w')
    p = subprocess.Popen(["find", "/", "-perm", "-4000"], stdout=subprocess.PIPE, stderr=FNULL)
    out, _ = p.communicate()
    return [x for x in out.split("\n") if x != ""]

def is_redirect_for_suid(magic, suid):
    bytes_to_read = len(magic) / 2
    try:
        with open(suid, "rb") as f:
            tmp = binascii.hexlify(f.read(bytes_to_read)).lower()
            if tmp == magic.lower():
                return True
    except:
        print "[*] Cant read {}".format(suid)
        return False

def find_shadow_suids(binfmt_path):
    expected = ["register", "status"]
    suids = get_suid_binaries()

    for i in os.listdir(binfmt_path):
        if i not in expected:
            print "[+] Checking binfmt rule {}....".format(i)
            interpreter = ""
            magic = ""
            flags = ""
            contents = open(os.path.join(binfmt_path, i)).read().split("\n")
            for c in contents:
                if c.startswith("interpreter"): interpreter = c.replace("interpreter ", "")
                if c.startswith("magic"): magic = c.replace("magic ", "")
                if c.startswith("flags"): flags = c.replace("flags: ", "")
           
            if "C" in flags:
                for s in suids:
                    if is_redirect_for_suid(magic, s):
                        print "[!] SUID binary {} has been redirected to {}".format(s, interpreter)

if __name__ == "__main__":
    print """
          $$\                       $$\                         $$\   $$\                      $$\                         
          $$ |                      $$ |                        $$ |  $$ |                     $$ |                        
 $$$$$$$\ $$$$$$$\   $$$$$$\   $$$$$$$ | $$$$$$\  $$\  $$\  $$\ $$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  
$$  _____|$$  __$$\  \____$$\ $$  __$$ |$$  __$$\ $$ | $$ | $$ |$$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ 
\$$$$$$\  $$ |  $$ | $$$$$$$ |$$ /  $$ |$$ /  $$ |$$ | $$ | $$ |$$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|
 \____$$\ $$ |  $$ |$$  __$$ |$$ |  $$ |$$ |  $$ |$$ | $$ | $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |      
$$$$$$$  |$$ |  $$ |\$$$$$$$ |\$$$$$$$ |\$$$$$$  |\$$$$$\$$$$  |$$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      
\_______/ \__|  \__| \_______| \_______| \______/  \_____\____/ \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      
                            v0.1 (c) 2019 BadHombres
                                                                                                                           
"""
    try:
        binfmt_dir = get_binfmt_dir()
        find_shadow_suids(binfmt_dir)
    except Exception as ex:
        print "[!] Error: {} ".format(ex)

