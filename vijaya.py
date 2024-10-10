import os, sys
import readline
from time import sleep as timeout
from core.vjmcore import *

# Function to handle printing text via lolcat
def lolcat_print(text):
    with open("temp_text.txt", "w") as f:
        f.write(text)
    os.system('cat temp_text.txt | lolcat')
    os.remove("temp_text.txt")

def main():
    banner()
    menu = """
   [01] Information Gathering
   [02] Vulnerability Analysis
   [03] Web Hacking
   [04] Database Assessment
   [05] Password Attacks
   [06] Wireless Attacks
   [07] Reverse Engineering
   [08] Exploitation Tools
   [09] Sniffing and Spoofing
   [10] Reporting Tools
   [11] Forensic Tools
   [12] Stress Testing
   [13] Install Linux Distro
   [14] Termux Utility
   [15] Shell Function [.bashrc]
   [16] Install CLI Games
   [17] Malware Analysis
   [18] Compiler/Interpreter
   [19] Social Engineering Tools
   [99] Update the vijaya
   [00] Exit the vijaya
"""
    lolcat_print(menu)

    vijaya = input("vjya > select > ")

    # 01 - Information Gathering
    if vijaya.strip() == "1" or vijaya.strip() == "01":
        info_menu = ""
        lolcat_print("\n    [01] Nmap: Utility for network discovery and security auditing")
        lolcat_print("    [02] Red Hawk: Information Gathering, Vulnerability Scanning and Crawling")
        lolcat_print("    [03] D-TECT: All-In-One Tool for Penetration Testing")
        lolcat_print("    [04] sqlmap: Automatic SQL injection and database takeover tool")
        lolcat_print("    [05] Infoga: Tool for Gathering Email Accounts Informations")
        lolcat_print("    [06] ReconDog: Information Gathering and Vulnerability Scanner tool")
        lolcat_print("    [07] AndroZenmap")
        lolcat_print("    [08] sqlmate: A friend of SQLmap which will do what you always expected from SQLmap")
        lolcat_print("    [09] AstraNmap: Security scanner used to find hosts and services on a computer network")
        lolcat_print("    [10] MapEye: Accurate GPS Location Tracker (Android, IOS, Windows phones)")
        lolcat_print("    [11] Easymap: Nmap Shortcut")
        lolcat_print("    [12] BlackBox: A Penetration Testing Framework")
        lolcat_print("    [13] XD3v: Powerful tool that lets you know all the essential details about your phone")
        lolcat_print("    [14] Crips: This Tools is a collection of online IP Tools that can be used to quickly get information about IP Address's, Web Pages and DNS records")
        lolcat_print("    [15] SIR: Resolve from the net the last known ip of a Skype Name")
        lolcat_print("    [16] EvilURL: Generate unicode evil domains for IDN Homograph Attack and detect them")
        lolcat_print("    [17] Striker: Recon & Vulnerability Scanning Suite")
        lolcat_print("    [18] Xshell: ToolKit")
        lolcat_print("    [19] OWScan: OVID Web Scanner")
        lolcat_print("    [20] OSIF: Open Source Information Facebook")
        lolcat_print("    [21] Devploit: Simple Information Gathering Tool")
        lolcat_print("    [22] Namechk: Osint tool based on namechk.com for checking usernames on more than 100 websites, forums and social networks")
        lolcat_print("    [23] AUXILE: Web Application Analysis Framework")
        lolcat_print("    [24] inther: Information gathering using shodan, censys and hackertarget")
        lolcat_print("    [25] GINF: GitHub Information Gathering Tool")
        lolcat_print("    [26] GPS Tracking")
        lolcat_print("    [27] ASU: Facebook Hacking ToolKit")
        lolcat_print("    [28] fim: Facebook Image Downloader")
        lolcat_print("    [29] MaxSubdoFinder: Tool for Discovering Subdomain")
        lolcat_print("    [30] pwnedOrNot: OSINT Tool for Finding Passwords of Compromised Email Accounts")
        lolcat_print("    [31] Mac-Lookup: Finds information about a Particular Mac address")
        lolcat_print("    [32] BillCipher: Information Gathering tool for a Website or IP address")
        lolcat_print("    [33] dnsrecon: Security assessment and network troubleshooting")
        lolcat_print("    [34] zphisher: Automated Phishing Tool")
        lolcat_print("    [35] Mr.SIP: SIP-Based Audit and Attack Tool")
        lolcat_print("    [36] Sherlock: Hunt down social media accounts by username")
        lolcat_print("    [37] userrecon: Find usernames across over 75 social networks")
        lolcat_print("    [38] PhoneInfoga: One of the most advanced tools to scan phone numbers using only free resources")
        lolcat_print("    [39] SiteBroker: A cross-platform python based utility for information gathering and penetration testing automation")
        lolcat_print("    [40] maigret: Collect a dossier on a person by username from thousands of sites")
        lolcat_print("    [41] GatheTOOL: Information Gathering - API hackertarget.com")
        lolcat_print("    [42] ADB-ToolKit")
        lolcat_print("    [43] TekDefense-Automater: Automater - IP URL and MD5 OSINT Analysis")
        lolcat_print("    [44] EagleEye: Stalk your Friends. Find their Instagram, FB and Twitter Profiles using Image Recognition and Reverse Image Search")
        lolcat_print("    [45] EyeWitness: EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible")
        lolcat_print("    [46] InSpy: A python based LinkedIn enumeration tool")
        lolcat_print("    [47] Leaked: Leaked? 2.1 - A Checking tool for Hash codes, Passwords and Emails leaked")
        lolcat_print("    [48] fierce: A DNS reconnaissance tool for locating non-contiguous IP space")
        lolcat_print("    [49] gasmask: Information gathering tool - OSINT")
        lolcat_print("    [50] osi.ig: Information Gathering (Instagram)")
        lolcat_print("    [51] proxy-checker: The simple script, which checks good and bad proxies")
        lolcat_print("\n    [00] Back to main menu\n")
        infogathering = input("vjya > select > ") 
        if infogathering == "@":
            infogathering = ""
            for x in range(1,201):
                infogathering += f"{x} "
        if len(infogathering.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for infox in infogathering.split():
            if infox.strip() == "01" or infox.strip() == "1": nmap()
            elif infox.strip() == "02" or infox.strip() == "2": red_hawk()
            elif infox.strip() == "03" or infox.strip() == "3": dtect()
            elif infox.strip() == "04" or infox.strip() == "4": sqlmap()
            elif infox.strip() == "05" or infox.strip() == "5": infoga()
            elif infox.strip() == "06" or infox.strip() == "6": reconDog()
            elif infox.strip() == "07" or infox.strip() == "7": androZenmap()
            elif infox.strip() == "08" or infox.strip() == "8": sqlmate()
            elif infox.strip() == "09" or infox.strip() == "9": astraNmap()
            elif infox.strip() == "10": mapeye()
            elif infox.strip() == "11": easyMap()
            elif infox.strip() == "12": blackbox()
            elif infox.strip() == "13": xd3v()
            elif infox.strip() == "14": crips()
            elif infox.strip() == "15": sir()
            elif infox.strip() == "16": evilURL()
            elif infox.strip() == "17": striker()
            elif infox.strip() == "18": xshell()
            elif infox.strip() == "19": owscan()
            elif infox.strip() == "20": osif()
            elif infox.strip() == "21": devploit()
            elif infox.strip() == "22": namechk()
            elif infox.strip() == "23": auxile()
            elif infox.strip() == "24": inther()
            elif infox.strip() == "25": ginf()
            elif infox.strip() == "26": gpstr()
            elif infox.strip() == "27": asu()
            elif infox.strip() == "28": fim()
            elif infox.strip() == "29": maxsubdofinder()
            elif infox.strip() == "30": pwnedOrNot()
            elif infox.strip() == "31": maclook()
            elif infox.strip() == "32": billcypher()
            elif infox.strip() == "33": dnsrecon()
            elif infox.strip() == "34": zphisher()
            elif infox.strip() == "35": mrsip()
            elif infox.strip() == "36": sherlock()
            elif infox.strip() == "37": userrecon()
            elif infox.strip() == "38": phoneinfoga()
            elif infox.strip() == "39": sitebroker()
            elif infox.strip() == "40": maigret()
            elif infox.strip() == "41": gathetool()
            elif infox.strip() == "42": adbtk()
            elif infox.strip() == "43": tekdefense()
            elif infox.strip() == "44": eagleeye()
            elif infox.strip() == "45": eyewitness()
            elif infox.strip() == "46": inspy()
            elif infox.strip() == "47": leaked()
            elif infox.strip() == "48": fierce()
            elif infox.strip() == "49": gasmask()
            elif infox.strip() == "50": osi_ig()
            elif infox.strip() == "51": proxy_checker()
            elif infox.strip() == "00" or infox.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)

    # 02 - Vulnerability Analysis
    elif vijaya.strip() == "2" or vijaya.strip() == "02":
        lolcat_print("\n    [01] Nmap: Utility for network discovery and security auditing")
        lolcat_print("    [02] AndroZenmap")
        lolcat_print("    [03] AstraNmap: Security scanner used to find hosts and services on a computer network")
        lolcat_print("    [04] Easymap: Nmap Shortcut")
        lolcat_print("    [05] Red Hawk: Information Gathering, Vulnerability Scanning and Crawling")
        lolcat_print("    [06] D-TECT: All-In-One Tool for Penetration Testing")
        lolcat_print("    [07] Damn Small SQLi Scanner: A fully functional SQL injection vulnerability scanner (supporting GET and POST parameters) written in under 100 lines of code")
        lolcat_print("    [08] SQLiv: massive SQL injection vulnerability scanner")
        lolcat_print("    [09] sqlmap: Automatic SQL injection and database takeover tool")
        lolcat_print("    [10] sqlscan: Quick SQL Scanner, Dorker, Webshell injector PHP")
        lolcat_print("    [11] Wordpresscan: WPScan rewritten in Python + some WPSeku ideas")
        lolcat_print("    [12] WPScan: Free wordPress security scanner")
        lolcat_print("    [13] sqlmate: A friend of SQLmap which will do what you always expected from SQLmap")
        lolcat_print("    [14] termux-wordpresscan")
        lolcat_print("    [15] TM-scanner: websites vulnerability scanner for termux")
        lolcat_print("    [16] Rang3r: Multi Thread IP + Port Scanner")
        lolcat_print("    [17] Striker: Recon & Vulnerability Scanning Suite")
        lolcat_print("    [18] Routersploit: Exploitation Framework for Embedded Devices")
        lolcat_print("    [19] Xshell: ToolKit")
        lolcat_print("    [20] SH33LL: Shell Scanner")
        lolcat_print("    [21] BlackBox: A Penetration Testing Framework")
        lolcat_print("    [22] XAttacker: Website Vulnerability Scanner & Auto Exploiter")
        lolcat_print("    [23] OWScan: OVID Web Scanner")
        lolcat_print("    [24] XPL-SEARCH: Search exploits in multiple exploit databases")
        lolcat_print("    [25] AndroBugs_Framework: An efficient Android vulnerability scanner that helps developers or hackers find potential security vulnerabilities in Android applications")
        lolcat_print("    [26] Clickjacking-Tester: A python script designed to check if the website if vulnerable of clickjacking and create a poc")
        lolcat_print("    [27] Sn1per: Attack Surface Management Platform | Sn1perSecurity LLC")
        lolcat_print("\n    [00] Back to main menu\n")
        vulnsys = input("vjya > select > ")
        if vulnsys == "@":
            vulnsys = ""
            for x in range(1,201):
                vulnsys += f"{x} "
        if len(vulnsys.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for vulnx in vulnsys.split():
            if vulnsys.strip() == "01" or vulnsys.strip() == "1": nmap()
            elif vulnsys.strip() == "02" or vulnsys.strip() == "2": androZenmap()
            elif vulnsys.strip() == "03" or vulnsys.strip() == "3": astraNmap()
            elif vulnsys.strip() == "04" or vulnsys.strip() == "4": easyMap()
            elif vulnsys.strip() == "05" or vulnsys.strip() == "5": red_hawk()
            elif vulnsys.strip() == "06" or vulnsys.strip() == "6": dtect()
            elif vulnsys.strip() == "07" or vulnsys.strip() == "7": dsss()
            elif vulnsys.strip() == "08" or vulnsys.strip() == "8": sqliv()
            elif vulnsys.strip() == "09" or vulnsys.strip() == "9": sqlmap()
            elif vulnsys.strip() == "10": sqlscan()
            elif vulnsys.strip() == "11": wordpreSScan()
            elif vulnsys.strip() == "12": wpscan()
            elif vulnsys.strip() == "13": sqlmate()
            elif vulnsys.strip() == "14": wordpresscan()
            elif vulnsys.strip() == "15": tmscanner()
            elif vulnsys.strip() == "16": rang3r()
            elif vulnsys.strip() == "17": striker()
            elif vulnsys.strip() == "18": routersploit()
            elif vulnsys.strip() == "19": xshell()
            elif vulnsys.strip() == "20": sh33ll()
            elif vulnsys.strip() == "21": blackbox()
            elif vulnsys.strip() == "22": xattacker()
            elif vulnsys.strip() == "23": owscan()
            elif vulnsys.strip() == "24": xplsearch()
            elif vulnsys.strip() == "25": androbugs()
            elif vulnsys.strip() == "26": clickjacking()
            elif vulnsys.strip() == "27": sn1per()
            elif vulnsys.strip() == "00" or vulnsys.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)

    # 03 - Web Hacking
    elif vijaya.strip() == "3" or vijaya.strip() == "03":
        lolcat_print("\n    [01] sqlmap: Automatic SQL injection and database takeover tool")
        lolcat_print("    [02] WebDAV: WebDAV File Upload Exploiter")
        lolcat_print("    [03] MaxSubdoFinder: Tool for Discovering Subdomain")
        lolcat_print("    [04] Webdav Mass Exploit")
        lolcat_print("    [05] Atlas: Quick SQLMap Tamper Suggester")
        lolcat_print("    [06] sqldump: Dump sql result sites with easy")
        lolcat_print("    [07] Websploit: An advanced MiTM Framework")
        lolcat_print("    [08] sqlmate: A friend of SQLmap which will do what you always expected from SQLmap")
        lolcat_print("    [09] inther: Information gathering using shodan, censys and hackertarget")
        lolcat_print("    [10] HPB: HTML Pages Builder")
        lolcat_print("    [11] Xshell: ToolKit")
        lolcat_print("    [12] SH33LL: Shell Scanner")
        lolcat_print("    [13] XAttacker: Website Vulnerability Scanner & Auto Exploiter")
        lolcat_print("    [14] XSStrike: Most advanced XSS Scanner")
        lolcat_print("    [15] Breacher: An advanced multithreaded admin panel finder")
        lolcat_print("    [16] OWScan: OVID Web Scanner")
        lolcat_print("    [17] ko-dork: A simple vuln web scanner")
        lolcat_print("    [18] ApSca: Powerful web penetration application")
        lolcat_print("    [19] amox: Find backdoor or shell planted on a site via dictionary attack")
        lolcat_print("    [20] FaDe: Fake deface with kindeditor, fckeditor and webdav")
        lolcat_print("    [21] AUXILE: Auxile Framework")
        lolcat_print("    [22] xss-payload-list: Cross Site Scripting ( XSS ) Vulnerability Payload List")
        lolcat_print("    [23] Xadmin: Admin Panel Finder")
        lolcat_print("    [24] CMSeeK: CMS Detection and Exploitation suite - Scan WordPress, Joomla, Drupal and over 180 other CMSs")
        lolcat_print("    [25] CMSmap: A python open source CMS scanner that automates the process of detecting security flaws of the most popular CMSs")
        lolcat_print("    [26] CrawlBox: Easy way to brute-force web directory")
        lolcat_print("    [27] LFISuite: Totally Automatic LFI Exploiter (+ Reverse Shell) and Scanner")
        lolcat_print("    [28] Parsero: Robots.txt audit tool")
        lolcat_print("    [29] Sn1per: Attack Surface Management Platform | Sn1perSecurity LLC")
        lolcat_print("    [30] Sublist3r: Fast subdomains enumeration tool for penetration testers")
        lolcat_print("    [31] WP-plugin-scanner: A tool to list plugins installed on a wordpress powered website")
        lolcat_print("    [32] WhatWeb: Next generation web scanner")
        lolcat_print("    [33] fuxploider: File upload vulnerability scanner and exploitation tool")
        lolcat_print("\n    [00] Back to main menu\n")
        webhack = input("vjya > select > ")
        if webhack == "@":
            webhack = ""
            for x in range(1,201):
                webhack += f"{x} "
        if len(webhack.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for webhx in webhack.split():
            if webhx.strip() == "01" or webhx.strip() == "1": sqlmap()
            elif webhx.strip() == "02" or webhx.strip() == "2": webdav()
            elif webhx.strip() == "03" or webhx.strip() == "3": maxsubdofinder()
            elif webhx.strip() == "04" or webhx.strip() == "4": webmassploit()
            elif webhx.strip() == "05" or webhx.strip() == "5": atlas()
            elif webhx.strip() == "06" or webhx.strip() == "6": sqldump()
            elif webhx.strip() == "07" or webhx.strip() == "7": websploit()
            elif webhx.strip() == "08" or webhx.strip() == "8": sqlmate()
            elif webhx.strip() == "09" or webhx.strip() == "9": inther()
            elif webhx.strip() == "10": hpb()
            elif webhx.strip() == "11": xshell()
            elif webhx.strip() == "12": sh33ll()
            elif webhx.strip() == "13": xattacker()
            elif webhx.strip() == "14": xsstrike()
            elif webhx.strip() == "15": breacher()
            elif webhx.strip() == "16": owscan()
            elif webhx.strip() == "17": kodork()
            elif webhx.strip() == "18": apsca()
            elif webhx.strip() == "19": amox()
            elif webhx.strip() == "20": fade()
            elif webhx.strip() == "21": auxile()
            elif webhx.strip() == "22": xss_payload_list()
            elif webhx.strip() == "23": xadmin()
            elif webhx.strip() == "24": cmseek()
            elif webhx.strip() == "25": cmsmap()
            elif webhx.strip() == "26": crawlbox()
            elif webhx.strip() == "27": lfisuite()
            elif webhx.strip() == "28": parsero()
            elif webhx.strip() == "29": sn1per()
            elif webhx.strip() == "30": sublist3r()
            elif webhx.strip() == "31": wppluginscanner()
            elif webhx.strip() == "32": whatweb()
            elif webhx.strip() == "33": fuxploider()
            elif webhx.strip() == "00" or webhx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 04 - Database Assessment
    elif vijaya.strip() == "4" or vijaya.strip() == "04":
        lolcat_print("\n    [01] DbDat: DbDat performs numerous checks on a database to evaluate security")
        lolcat_print("    [02] sqlmap: Automatic SQL injection and database takeover tool")
        lolcat_print("    [03] NoSQLMap: Automated NoSQL database enumeration and web application exploitation tool")
        lolcat_print("    [04] audit_couchdb: Detect security issues, large or small, in a CouchDB server")
        lolcat_print("    [05] mongoaudit: An automated pentesting tool that lets you know if your MongoDB instances are properly secured")
        lolcat_print("\n    [00] Back to main menu\n")
        dbssm = input("vjya > select > ")
        if dbssm == "@":
            dbssm = ""
            for x in range(1,201):
                dbssm += f"{x} "
        if len(dbssm.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for dbsx in dbssm.split():
            if dbsx.strip() == "01" or dbsx.strip() == "1": dbdat()
            elif dbsx.strip() == "02" or dbsx.strip() == "2": sqlmap()
            elif dbsx.strip() == "03" or dbsx.strip() == "3": nosqlmap
            elif dbsx.strip() == "04" or dbsx.strip() == "4": audit_couchdb()
            elif dbsx.strip() == "05" or dbsx.strip() == "5": mongoaudit()
            elif dbsx.strip() == "00" or dbsx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 05 - Password Attacks
    elif vijaya.strip() == "5" or vijaya.strip() == "05":
        lolcat_print("\n    [01] Hydra: Network logon cracker supporting different services")
        lolcat_print("    [02] FMBrute: Facebook Multi Brute Force")
        lolcat_print("    [03] HashID: Software to identify the different types of hashes")
        lolcat_print("    [04] Facebook Brute Force 3")
        lolcat_print("    [05] Black Hydra: A small program to shorten brute force sessions on hydra")
        lolcat_print("    [06] Hash Buster: Crack hashes in seconds")
        lolcat_print("    [07] FBBrute: Facebook Brute Force")
        lolcat_print("    [08] Cupp: Common User Passwords Profiler")
        lolcat_print("    [09] InstaHack: Instagram Brute Force")
        lolcat_print("    [10] Indonesian Wordlist")
        lolcat_print("    [11] Xshell")
        lolcat_print("    [12] Aircrack-ng: WiFi security auditing tools suite")
        lolcat_print("    [13] BlackBox: A Penetration Testing Framework")
        lolcat_print("    [14] Katak: An open source software login brute-forcer toolkit and hash decrypter")
        lolcat_print("    [15] Hasher: Hash cracker with auto detect hash")
        lolcat_print("    [16] Hash-Generator: Beautiful Hash Generator")
        lolcat_print("    [17] nk26: Nkosec Encode")
        lolcat_print("    [18] Hasherdotid: A tool for find an encrypted text")
        lolcat_print("    [19] Crunch: Highly customizable wordlist generator")
        lolcat_print("    [20] Hashcat: World's fastest and most advanced password recovery utility")
        lolcat_print("    [21] ASU: Facebook Hacking ToolKit")
        lolcat_print("    [22] Credmap: An open source tool that was created to bring awareness to the dangers of credential reuse")
        lolcat_print("    [23] BruteX: Automatically brute force all services running on a target")
        lolcat_print("    [24] Gemail-Hack: python script for Hack gmail account brute force")
        lolcat_print("    [25] GoblinWordGenerator: Python wordlist generator")
        lolcat_print("    [26] PyBozoCrack: A silly & effective MD5 cracker in Python")
        lolcat_print("    [27] brutespray: Brute-Forcing from Nmap output - Automatically attempts default creds on found services")
        lolcat_print("    [28] crowbar: Crowbar is brute forcing tool that can be used during penetration tests")
        lolcat_print("    [29] elpscrk: An Intelligent wordlist generator based on user profiling, permutations, and statistics")
        lolcat_print("    [30] fbht: Facebook Hacking Tool")
        lolcat_print("\n    [00] Back to main menu\n")
        passtak = input("vjya > select > ")
        if passtak == "@":
            passtak = ""
            for x in range(1,201):
                passtak += f"{x} "
        if len(passtak.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for passx in passtak.split():
            if passx.strip() == "01" or passx.strip() == "1": hydra()
            elif passx.strip() == "02" or passx.strip() == "2": fmbrute()
            elif passx.strip() == "03" or passx.strip() == "3": hashid()
            elif passx.strip() == "04" or passx.strip() == "4": fbBrute()
            elif passx.strip() == "05" or passx.strip() == "5": black_hydra()
            elif passx.strip() == "06" or passx.strip() == "6": hash_buster()
            elif passx.strip() == "07" or passx.strip() == "7": fbbrutex()
            elif passx.strip() == "08" or passx.strip() == "8": cupp()
            elif passx.strip() == "09" or passx.strip() == "9": instaHack()
            elif passx.strip() == "10": indonesian_wordlist()
            elif passx.strip() == "11": xshell()
            elif passx.strip() == "12": aircrackng()
            elif passx.strip() == "13": blackbox()
            elif passx.strip() == "14": katak()
            elif passx.strip() == "15": hasher()
            elif passx.strip() == "16": hashgenerator()
            elif passx.strip() == "17": nk26()
            elif passx.strip() == "18": hasherdotid()
            elif passx.strip() == "19": crunch()
            elif passx.strip() == "20": hashcat()
            elif passx.strip() == "21": asu()
            elif passx.strip() == "22": credmap()
            elif passx.strip() == "23": brutex()
            elif passx.strip() == "24": gemailhack()
            elif passx.strip() == "25": goblinwordgenerator()
            elif passx.strip() == "26": pybozocrack()
            elif passx.strip() == "27": brutespray()
            elif passx.strip() == "28": crowbar()
            elif passx.strip() == "29": elpscrk()
            elif passx.strip() == "30": fbht()
            elif passx.strip() == "00" or passx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 06 - Wireless Attacks
    elif vijaya.strip() == "6" or vijaya.strip() == "06":
        lolcat_print("\n    [01] Aircrack-ng: WiFi security auditing tools suite")
        lolcat_print("    [02] Wifite: An automated wireless attack tool")
        lolcat_print("    [03] Wifiphisher: The Rogue Access Point Framework")
        lolcat_print("    [04] Routersploit: Exploitation Framework for Embedded Devices")
        lolcat_print("    [05] PwnSTAR: (Pwn SofT-Ap scRipt) - for all your fake-AP needs!")
        lolcat_print("    [06] Pyrit: The famous WPA precomputed cracker, Migrated from Google")
        lolcat_print("\n    [00] Back to main menu\n")
        wiretak = input("vjya > select > ")
        if wiretak == "@":
            wiretak = ""
            for x in range(1,201):
                wiretak += f"{x} "
        if len(wiretak.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for wirex in wiretak.split():
            if wirex.strip() == "01" or wirex.strip() == "1": aircrackng()
            elif wirex.strip() == "02" or wirex.strip() == "2": wifite()
            elif wirex.strip() == "03" or wirex.strip() == "3": wifiphisher()
            elif wirex.strip() == "04" or wirex.strip() == "4": routersploit()
            elif wirex.strip() == "05" or wirex.strip() == "5": pwnstar()
            elif wirex.strip() == "06" or wirex.strip() == "6": pyrit()
            elif wirex.strip() == "00" or wirex.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 07 - Reverse Engineering
    elif vijaya.strip() == "7" or vijaya.strip() == "07":
        lolcat_print("\n    [01] Binary Exploitation")
        lolcat_print("    [02] jadx: DEX to JAVA Decompiler")
        lolcat_print("    [03] apktool: A utility that can be used for reverse engineering Android applications")
        lolcat_print("    [04] uncompyle6: Python cross-version byte-code decompiler")
        lolcat_print("    [05] ddcrypt: DroidScript APK Deobfuscator")
        lolcat_print("    [06] CFR: Yet another java decompiler")
        lolcat_print("    [07] UPX: Ultimate Packer for eXecutables")
        lolcat_print("    [08] pyinstxtractor: PyInstaller Extractor")
        lolcat_print("    [09] innoextract: A tool to unpack installers created by Inno Setup")
        lolcat_print("    [10] pycdc: C++ python bytecode disassembler and decompiler")
        lolcat_print("    [11] APKiD: Android Application Identifier for Packers, Protectors, Obfuscators and Oddities - PEiD for Android")
        lolcat_print("    [12] DTL-X: Python APK Reverser & Patcher Tool")
        lolcat_print("    [13] APKLeaks: Scanning APK file for URIs, endpoints & secrets")
        lolcat_print("    [14] apk-mitm: A CLI application that automatically prepares Android APK files for HTTPS inspection")
        lolcat_print("    [15] ssl-pinning-remover: An SSL Pinning Remover for Android Apps")
        lolcat_print("    [16] GEF: GEF (GDB Enhanced Features) - a modern experience for GDB with advanced debugging capabilities for exploit devs & reverse engineers on Linux")
        lolcat_print("\n    [00] Back to main menu\n")
        reversi = input("vjya > select > ")
        if reversi == "@":
            reversi = ""
            for x in range(1,201):
                reversi += f"{x} "
        if len(reversi.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for revex in reversi.split():
            if revex.strip() == "01" or revex.strip() == "1": binploit()
            elif revex.strip() == "02" or revex.strip() == "2": jadx()
            elif revex.strip() == "03" or revex.strip() == "3": apktool()
            elif revex.strip() == "04" or revex.strip() == "4": uncompyle()
            elif revex.strip() == "05" or revex.strip() == "5": ddcrypt()
            elif revex.strip() == "06" or revex.strip() == "6": cfr()
            elif revex.strip() == "07" or revex.strip() == "7": upx()
            elif revex.strip() == "08" or revex.strip() == "8": pyinstxtractor()
            elif revex.strip() == "09" or revex.strip() == "9": innoextract()
            elif revex.strip() == "10": pycdc()
            elif revex.strip() == "11": apkid()
            elif revex.strip() == "12": dtlx()
            elif revex.strip() == "13": apkleaks()
            elif revex.strip() == "14": apkmitm()
            elif revex.strip() == "15": ssl_pinning_remover()
            elif revex.strip() == "16": gef()
            elif revex.strip() == "00" or revex.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 08 - Exploitation Tools
    elif vijaya.strip() == "8" or vijaya.strip() == "08":
        lolcat_print("\n    [01] Metasploit: Advanced open-source platform for developing, testing and using exploit code")
        lolcat_print("    [02] commix: Automated All-in-One OS Command Injection and Exploitation Tool")
        lolcat_print("    [03] BlackBox: A Penetration Testing Framework")
        lolcat_print("    [04] Brutal: Payload for teensy like a rubber ducky but the syntax is different")
        lolcat_print("    [05] TXTool: An easy pentesting tool")
        lolcat_print("    [06] XAttacker: Website Vulnerability Scanner & Auto Exploiter")  
        lolcat_print("    [07] Websploit: An advanced MiTM Framework")
        lolcat_print("    [08] Routersploit: Exploitation Framework for Embedded Devices")
        lolcat_print("    [09] A-Rat: Remote Administration Tool")
        lolcat_print("    [10] BAF: Blind Attacking Framework")
        lolcat_print("    [11] Gloom-Framework: Linux Penetration Testing Framework")
        lolcat_print("    [12] Zerodoor: A script written lazily for generating cross-platform  backdoors on the go :)")
        lolcat_print("\n    [00] Back to main menu\n")
        exploitool = input("vjya > select > ")
        if exploitool == "@":
            exploitool = ""
            for x in range(1,201):
                exploitool += f"{x} "
        if len(exploitool.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for explx in exploitool.split():
            if explx.strip() == "01" or explx.strip() == "1": metasploit()
            elif explx.strip() == "02" or explx.strip() == "2": commix()
            elif explx.strip() == "03" or explx.strip() == "3": blackbox()
            elif explx.strip() == "04" or explx.strip() == "4": brutal()
            elif explx.strip() == "05" or explx.strip() == "5": txtool()
            elif explx.strip() == "06" or explx.strip() == "6": xattacker()
            elif explx.strip() == "07" or explx.strip() == "7": websploit()
            elif explx.strip() == "08" or explx.strip() == "8": routersploit()
            elif explx.strip() == "09" or explx.strip() == "9": arat()
            elif explx.strip() == "10": baf()
            elif explx.strip() == "11": gloomframework()
            elif explx.strip() == "12": zerodoor()
            elif explx.strip() == "00" or explx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 09 - Sniffing and Spoofing
    elif vijaya.strip() == "9" or vijaya.strip() == "09":
        lolcat_print("\n    [01] KnockMail: Verify if Email Exists")
        lolcat_print("    [02] tcpdump: A powerful command-line packet analyzer")
        lolcat_print("    [03] Ettercap: Comprehensive suite for MITM attacks, can sniff live connections, do content filtering on the fly and much more")
        lolcat_print("    [04] hping3: hping is a command-line oriented TCP/IP packet assembler/analyzer")
        lolcat_print("    [05] tshark: Network protocol analyzer and sniffer")
        lolcat_print("\n    [00] Back to main menu\n")
        sspoof = input("vjya > select > ")
        if sspoof == "@":
            sspoof = ""
            for x in range(1,201):
                sspoof += f"{x} "
        if len(sspoof.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for sspx in sspoof.split():
            if sspx.strip() == "01" or sspx.strip() == "1": knockmail()
            elif sspx.strip() == "02" or sspx.strip() == "2": tcpdump()
            elif sspx.strip() == "03" or sspx.strip() == "3": ettercap()
            elif sspx.strip() == "04" or sspx.strip() == "4": hping3()
            elif sspx.strip() == "05" or sspx.strip() == "5": tshark()
            elif sspx.strip() == "00" or sspx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 10 - Reporting Tools
    elif vijaya.strip() == "10":
        lolcat_print("\n    [01] dos2unix: Converts between DOS and Unix text files")
        lolcat_print("    [02] exiftool: Utility for reading, writing and editing meta information in a wide variety of files")
        lolcat_print("    [03] iconv: Utility converting between different character encodings")
        lolcat_print("    [04] mediainfo: Command-line utility for reading information from media files")
        lolcat_print("    [05] pdfinfo: PDF document information extractor")
        lolcat_print("\n    [00] Back to main menu\n")
        reportls = input("vjya > select > ")
        if reportls == "@":
            reportls = ""
            for x in range(1,201):
                reportls += f"{x} "
        if len(reportls.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for reportx in reportls.split():
            if reportx.strip() == "01" or reportx.strip() == "1": dos2unix()
            elif reportx.strip() == "02" or reportx.strip() == "2": exiftool()
            elif reportx.strip() == "03" or reportx.strip() == "3": iconv()
            elif reportx.strip() == "04" or reportx.strip() == "4": mediainfo()
            elif reportx.strip() == "05" or reportx.strip() == "5": pdfinfo()
            elif reportx.strip() == "00" or reportx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 11 - Forensic Tools
    elif vijaya.strip() == "11":
        lolcat_print("\n    [01] steghide: Embeds a message in a file by replacing some of the least significant bits")
        lolcat_print("    [02] tesseract: Tesseract is probably the most accurate open source OCR engine available")
        lolcat_print("    [03] sleuthkit: The Sleuth Kit (TSK) is a library for digital forensics tools")
        lolcat_print("    [04] CyberScan: Network's Forensics ToolKit")
        lolcat_print("    [05] binwalk: Firmware analysis tool")
        lolcat_print("\n    [00] Back to main menu\n")
        forensc = input("vjya > select > ")
        if forensc == "@":
            forensc = ""
            for x in range(1,201):
                forensc += f"{x} "
        if len(forensc.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for forenx in forensc.split():
            if forenx.strip() == "01" or forenx.strip() == "1": steghide()
            elif forenx.strip() == "02" or forenx.strip() == "2": tesseract()
            elif forenx.strip() == "03" or forenx.strip() == "3": sleuthkit()
            elif forenx.strip() == "04" or forenx.strip() == "4": cyberscan()
            elif forenx.strip() == "05" or forenx.strip() == "5": binwalk()
            elif forenx.strip() == "00" or forenx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 12 - Stress Testing
    elif vijaya.strip() == "12":
        lolcat_print("\n    [01] Torshammer: Slow post DDOS tool")
        lolcat_print("    [02] Slowloris: Low bandwidth DoS tool")
        lolcat_print("    [03] Fl00d & Fl00d2: UDP Flood tool")
        lolcat_print("    [04] GoldenEye: GoldenEye Layer 7 (KeepAlive+NoCache) DoS test tool")
        lolcat_print("    [05] Xerxes: The most powerful DoS tool")
        lolcat_print("    [06] Planetwork-DDOS")
        lolcat_print("    [07] Xshell")
        lolcat_print("    [08] santet-online: Social Engineering Tool")
        lolcat_print("    [09] dost-attack: WebServer Attacking Tools")
        lolcat_print("    [10] DHCPig: DHCP exhaustion script written in python using scapy network library")
        lolcat_print("\n    [00] Back to main menu\n")
        stresstest = input("vjya > select > ")
        if stresstest == "@":
            stresstest = ""
            for x in range(1,201):
                stresstest += f"{x} "
        if len(stresstest.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for stressx in stresstest.split():
            if stressx.strip() == "01" or stressx.strip() == "1": torshammer()
            elif stressx.strip() == "02" or stressx.strip() == "2": slowloris()
            elif stressx.strip() == "03" or stressx.strip() == "3": fl00d12()
            elif stressx.strip() == "04" or stressx.strip() == "4": goldeneye()
            elif stressx.strip() == "05" or stressx.strip() == "5": xerxes()
            elif stressx.strip() == "06" or stressx.strip() == "6": planetwork_ddos()
            elif stressx.strip() == "07" or stressx.strip() == "7": xshell()
            elif stressx.strip() == "08" or stressx.strip() == "8": sanlen()
            elif stressx.strip() == "09" or stressx.strip() == "9": dostattack()
            elif stressx.strip() == "10": dhcpig()
            elif stressx.strip() == "00" or stressx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 13 - Install Linux Distro
    elif vijaya.strip() == "13":
        lolcat_print("\n    [01] Ubuntu (impish)")
        lolcat_print("    [02] Fedora")
        lolcat_print("    [03] Kali Nethunter")
        lolcat_print("    [04] Parrot")
        lolcat_print("    [05] Arch Linux")
        lolcat_print("    [06] Alpine Linux (edge)")
        lolcat_print("    [07] Debian (bullseye)")
        lolcat_print("    [08] Manjaro AArch64")
        lolcat_print("    [09] OpenSUSE (Tumbleweed)")
        lolcat_print("    [10] Void Linux")
        lolcat_print("\n    [00] Back to main menu\n")
        innudis = input("vjya > select > ")
        if innudis == "@":
            innudis = ""
            for x in range(1,201):
                innudis += f"{x} "
        if len(innudis.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for innux in innudis.split():
            if innux.strip() == "01" or innux.strip() == "1": ubuntu()
            elif innux.strip() == "02" or innux.strip() == "2": fedora()
            elif innux.strip() == "03" or innux.strip() == "3": nethunter()
            elif innux.strip() == "04" or innux.strip() == "4": parrot()
            elif innux.strip() == "05" or innux.strip() == "5": archlinux()
            elif innux.strip() == "06" or innux.strip() == "6": alpine()
            elif innux.strip() == "07" or innux.strip() == "7": debian()
            elif innux.strip() == "08" or innux.strip() == "8": manjaroArm64()
            elif innux.strip() == "09" or innux.strip() == "9": opensuse()
            elif innux.strip() == "10": voidLinux()
            elif innux.strip() == "00" or innux.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 14 - Termux Utility
    elif vijaya.strip() == "14":
        lolcat_print("\n    [01] SpiderBot: Curl website using random proxy and user agent")
        lolcat_print("    [02] Ngrok: tunnel local ports to public URLs and inspect traffic")
        lolcat_print("    [03] Sudo: sudo installer for Android")
        lolcat_print("    [04] google: Python bindings to the Google search engine")
        lolcat_print("    [05] kojawafft")
        lolcat_print("    [06] ccgen: Credit Card Generator")
        lolcat_print("    [07] VCRT: Virus Creator")
        lolcat_print("    [08] E-Code: PHP Script Encoder")
        lolcat_print("    [09] Termux-Styling")
        lolcat_print("    [11] xl-py: XL Direct Purchase Package")
        lolcat_print("    [12] BeanShell: A small, free, embeddable Java source interpreter with object scripting language features, written in Java")
        lolcat_print("    [13] vbug: Virus Maker")
        lolcat_print("    [14] Crunch: Highly customizable wordlist generator")
        lolcat_print("    [15] Textr: Simple tool for running text")
        lolcat_print("    [16] heroku: CLI to interact with Heroku")
        lolcat_print("    [17] RShell: Reverse shell for single listening")
        lolcat_print("    [18] TermPyter: Fix all error Jupyter installation on termux")
        lolcat_print("    [19] Numpy: The fundamental package for scientific computing with Python")
        lolcat_print("    [20] BTC-to-IDR-checker: Check the exchange rate virtual money currency to Indonesia Rupiah from Bitcoin.co.id API")
        lolcat_print("    [21] ClickBot: Earn money using telegram bot")
        lolcat_print("    [22] pandas: Powerful open-source data manipulation and analysis library")
        lolcat_print("    [23] jupyter-notebook: Interactive web application that allows users to create and share documents containing live code, equations, visualizations, and narrative text")
        lolcat_print("\n    [00] Back to main menu\n")
        moretool = input("vjya > select > ")
        if moretool == "@":
            moretool = ""
            for x in range(1,201):
                moretool += f"{x} "
        if len(moretool.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for moret in moretool.split():
            if moret.strip() == "01" or moret.strip() == "1": spiderbot()
            elif moret.strip() == "02" or moret.strip() == "2": ngrok()
            elif moret.strip() == "03" or moret.strip() == "3": sudo()
            elif moret.strip() == "04" or moret.strip() == "4": google()
            elif moret.strip() == "05" or moret.strip() == "5": kojawafft()
            elif moret.strip() == "06" or moret.strip() == "6": ccgen()
            elif moret.strip() == "07" or moret.strip() == "7": vcrt()
            elif moret.strip() == "08" or moret.strip() == "8": ecode()
            elif moret.strip() == "09" or moret.strip() == "9": stylemux()
            elif moret.strip() == "10": passgencvar()
            elif moret.strip() == "11": xlPy()
            elif moret.strip() == "12": beanshell()
            elif moret.strip() == "13": vbug()
            elif moret.strip() == "14": crunch()
            elif moret.strip() == "15": textr()
            elif moret.strip() == "16": heroku()
            elif moret.strip() == "17": rshell()
            elif moret.strip() == "18": termpyter()
            elif moret.strip() == "19": numpy()
            elif moret.strip() == "20": btc2idr()
            elif moret.strip() == "21": clickbot()
            elif moret.strip() == "22": pandas()
            elif moret.strip() == "23": notebook()
            elif moret.strip() == "00" or moret.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 15 - Shell Function [.bashrc]
    elif vijaya.strip() == "15":
        lolcat_print("\n    [01] FBVid (FB Video Downloader)")
        lolcat_print("    [02] cast2video (Asciinema Cast Converter)")
        lolcat_print("    [03] iconset (AIDE App Icon)")
        lolcat_print("    [04] readme (GitHub README.md)")
        lolcat_print("    [05] makedeb (DEB Package Builder)")
        lolcat_print("    [06] quikfind (Search Files)")
        lolcat_print("    [07] pranayama (4-7-8 Relax Breathing)")
        lolcat_print("    [08] sqlc (SQLite Query Processor)")
        lolcat_print("\n    [00] Back to main menu\n")
        myshf = input("vjya > select > ")
        if myshf == "@":
            myshf = ""
            for x in range(1,201):
                myshf += f"{x} "
        if len(myshf.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for mysh in myshf.split():
            if mysh.strip() == "01" or mysh.strip() == "1": fbvid()
            elif mysh.strip() == "02" or mysh.strip() == "2": cast2video()
            elif mysh.strip() == "03" or mysh.strip() == "3": iconset()
            elif mysh.strip() == "04" or mysh.strip() == "4": readme()
            elif mysh.strip() == "05" or mysh.strip() == "5": makedeb()
            elif mysh.strip() == "06" or mysh.strip() == "6": quikfind()
            elif mysh.strip() == "07" or mysh.strip() == "7": pranayama()
            elif mysh.strip() == "08" or mysh.strip() == "8": sqlc()
            elif mysh.strip() == "00" or mysh.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 16 - Install CLI Games
    elif vijaya.strip() == "16":
        lolcat_print("\n    [01] Flappy Bird")
        lolcat_print("    [02] Street Car")
        lolcat_print("    [03] Speed Typing")
        lolcat_print("    [04] NSnake: The classic snake game with textual interface")
        lolcat_print("    [05] Moon buggy: Simple game where you drive a car across the moon's surface")
        lolcat_print("    [06] Nudoku: ncurses based sudoku game")
        lolcat_print("    [07] tty-solitaire")
        lolcat_print("    [08] Pacman4Console")
        lolcat_print("\n    [00] Back to main menu\n")
        cligam = input("vjya > select > ")
        if cligam == "@":
            cligam = ""
            for x in range(1,201):
                cligam += f"{x} "
        if len(cligam.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for clig in cligam.split():
            if clig.strip() == "01" or clig.strip() == "1": flappy_bird()
            elif clig.strip() == "02" or clig.strip() == "2": street_car()
            elif clig.strip() == "03" or clig.strip() == "3": speed_typing()
            elif clig.strip() == "04" or clig.strip() == "4": nsnake()
            elif clig.strip() == "05" or clig.strip() == "5": moon_buggy()
            elif clig.strip() == "06" or clig.strip() == "6": nudoku()
            elif clig.strip() == "07" or clig.strip() == "7": ttysolitaire()
            elif clig.strip() == "08" or clig.strip() == "8": pacman4console()
            elif clig.strip() == "00" or clig.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 17 - Malware Analysis
    elif vijaya.strip() == "17":
        lolcat_print("\n    [01] Lynis: Security Auditing and Rootkit Scanner")
        lolcat_print("    [02] Chkrootkit: A Linux Rootkit Scanners")
        lolcat_print("    [03] ClamAV: Antivirus Software Toolkit")
        lolcat_print("    [04] Yara: Tool aimed at helping malware researchers to identify and classify malware samples")
        lolcat_print("    [05] VirusTotal-CLI: Command line interface for VirusTotal")
        lolcat_print("    [06] avpass: Tool for leaking and bypassing Android malware detection system")
        lolcat_print("    [07] DKMC: Dont kill my cat - Malicious payload evasion tool")
        lolcat_print("\n    [00] Back to main menu\n")
        malsys = input("vjya > select > ")
        if malsys == "@":
            malsys = ""
            for x in range(1,201):
                malsys += f"{x} "
        if len(malsys.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for malx in malsys.split():
            if malx.strip() == "01" or malx.strip() == "1": lynis()
            elif malx.strip() == "02" or malx.strip() == "2": chkrootkit()
            elif malx.strip() == "03" or malx.strip() == "3": clamav()
            elif malx.strip() == "04" or malx.strip() == "4": yara()
            elif malx.strip() == "05" or malx.strip() == "5": virustotal()
            elif malx.strip() == "06" or malx.strip() == "6": avpass()
            elif malx.strip() == "07" or malx.strip() == "7": dkmc()
            elif malx.strip() == "00" or malx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 18 - Compiler/Interpreter
    elif vijaya.strip() == "18":
        lolcat_print("\n    [01] Python2: Python 2 programming language intended to enable clear programs")
        lolcat_print("    [02] ecj: Eclipse Compiler for Java")
        lolcat_print("    [03] Golang: Go programming language compiler")
        lolcat_print("    [04] ldc: D programming language compiler, built with LLVM")
        lolcat_print("    [05] Nim: Nim programming language compiler")
        lolcat_print("    [06] shc: Shell script compiler")
        lolcat_print("    [07] TCC: Tiny C Compiler")
        lolcat_print("    [08] PHP: Server-side, HTML-embedded scripting language")
        lolcat_print("    [09] Ruby: Dynamic programming language with a focus on simplicity and productivity")
        lolcat_print("    [10] Perl: Capable, feature-rich programming language")
        lolcat_print("    [11] Vlang: Simple, fast, safe, compiled language for developing maintainable software")
        lolcat_print("    [12] BeanShell: Small, free, embeddable, source level Java interpreter with object based scripting language features written in Java")
        lolcat_print("    [13] fp-compiler: Free Pascal is a 32, 64 and 16 bit professional Pascal compiler")
        lolcat_print("    [14] Octave: Scientific Programming Language")
        lolcat_print("    [15] BlogC: A blog compiler")
        lolcat_print("    [16] Dart: General-purpose programming language")
        lolcat_print("    [17] Yasm: Assembler supporting the x86 and AMD64 instruction sets")
        lolcat_print("    [18] Nasm: A cross-platform x86 assembler with an Intel-like syntax.")
        lolcat_print("\n    [00] Back to main menu\n")
        compter = input("vjya > select > ")
        if compter == "@":
            compter = ""
            for x in range(1,201):
                compter += f"{x} "
        if len(compter.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for compt in compter.split():
            if compt.strip() == "01" or compt.strip() == "1": python2()
            elif compt.strip() == "02" or compt.strip() == "2": ecj()
            elif compt.strip() == "03" or compt.strip() == "3": golang()
            elif compt.strip() == "04" or compt.strip() == "4": ldc()
            elif compt.strip() == "05" or compt.strip() == "5": nim()
            elif compt.strip() == "06" or compt.strip() == "6": shc()
            elif compt.strip() == "07" or compt.strip() == "7": tcc()
            elif compt.strip() == "08" or compt.strip() == "8": php()
            elif compt.strip() == "09" or compt.strip() == "9": ruby()
            elif compt.strip() == "10": perl()
            elif compt.strip() == "11": vlang()
            elif compt.strip() == "12": beanshell()
            elif compt.strip() == "13": fpcompiler()
            elif compt.strip() == "14": octave()
            elif compt.strip() == "15": blogc()
            elif compt.strip() == "16": dart()
            elif compt.strip() == "17": yasm()
            elif compt.strip() == "18": nasm()
            elif compt.strip() == "00" or compt.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 19 - Social Engineering Tools
    elif vijaya.strip() == "19":
        lolcat_print("\n    [01] weeman: HTTP server for phishing in python")
        lolcat_print("    [02] SocialFish: Educational Phishing Tool & Information Collector")
        lolcat_print("    [03] santet-online: Social Engineering Tool")
        lolcat_print("    [04] SpazSMS: Send unsolicited messages repeatedly on the same phone number")
        lolcat_print("    [05] LiteOTP: Multi Spam SMS OTP")
        lolcat_print("    [06] F4K3: Fake User Data Generator")
        lolcat_print("    [07] Hac")
        lolcat_print("    [08] Cookie-stealer: Crappy cookie stealer")
        lolcat_print("    [09] zphisher: Automated Phishing Tool")
        lolcat_print("    [10] Evilginx: Advanced Phishing With Two-factor Authentication Bypass")
        lolcat_print("    [11] ghost-phisher: Automatically exported from code.google.com/p/ghost-phisher")
        lolcat_print("\n    [00] Back to main menu\n")
        soceng = input("vjya > select > ")
        if soceng == "@":
            soceng = ""
            for x in range(1,201):
                soceng += f"{x} "
        if len(soceng.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for socng in soceng.split():
            if socng.strip() == "01" or socng.strip() == "1": weeman()
            elif socng.strip() == "02" or socng.strip() == "2": socfish()
            elif socng.strip() == "03" or socng.strip() == "3": sanlen()
            elif socng.strip() == "04" or socng.strip() == "4": spazsms()
            elif socng.strip() == "05" or socng.strip() == "5": liteotp()
            elif socng.strip() == "06" or socng.strip() == "6": f4k3()
            elif socng.strip() == "07" or socng.strip() == "7": hac()
            elif socng.strip() == "08" or socng.strip() == "8": cookiestealer()
            elif socng.strip() == "09" or socng.strip() == "9": zphisher()
            elif socng.strip() == "10": evilginx()
            elif socng.strip() == "11": ghostphisher()
            elif socng.strip() == "00" or socng.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    elif vijaya.strip() == "99":
        os.system("git pull")
    elif vijaya.strip() == "0" or vijaya.strip() == "00":
        sys.exit()
    
    else:
        print("\nERROR: Wrong Input")
        timeout(1)
        restart_program()

if __name__ == "__main__":
    os.system("clear")
    main()
