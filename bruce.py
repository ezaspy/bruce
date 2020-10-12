#!/usr/bin/env python3 -tt
import argparse, sys, os, shutil, io, time, re, json, subprocess
from contextlib import redirect_stdout
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("directory", nargs="+", help="Source directory where the packet capture files are located")
parser.add_argument("-e", "--export", help="Export object from PCAP", action='store_const', const=True, default=False)
parser.add_argument("-s", "--searchstring", help="Search for string within PCAP", action='store_const', const=True, default=False)

args = parser.parse_args()
directory, export, search = args.directory, args.export, args.searchstring
d = directory[0]

def main():
    subprocess.Popen(["clear"])
    time.sleep(0.2)
    print("\n\n\n      _______________________________     _________         .    .\n     /                               \\   (..       \\_    ,  |\\  /|\n     |  Fish are friends, not food.   \\   \\       O  \\  /|  \\ \\/ /\n     \\_______________________________  \\   \\______    \\/ |   \\  /\n                                     \\__\\     vvvv\\    \\ |   /  |\n                                              \\^^^^  ==   \\_/   |\n                                               `\\_   ===    \\.  |\n                                               / /\\_   \\ /      |\n                                               |/   \\_  \\|      /\n                                                      \\________/\n\n") # https://www.asciiart.eu/animals/fish
    time.sleep(2)
    for pcaproot, _, files in os.walk(d):
        for pcapfile in files:
            try:
                with open(os.path.join(pcaproot, pcapfile), "rb") as pcapcontent:
                    jsonlist, jsondict, objectlist = [], {}, ["dicom", "http", "imf", "smb", "tftp"]
                    if str(pcapcontent.readline())[2:42] == "\\xd4\\xc3\\xb2\\xa1\\x02\\x00\\x04\\x00\\x00\\x00":
                        print("      Processing {}...".format(pcapfile))
                        with open(os.path.join(pcaproot, pcapfile+".json"), "a") as pcapjson:
                            pcapjson.write(str(subprocess.Popen(["tshark", "-r", pcapfile, "-T", "json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()).replace("\\\\\\\\","\\").replace("\\\\\\","\\").replace("\\\\r\\\\n","").replace("\\r\\n","").replace("{\\n","{\n").replace("},\\n","},\n").replace("\"\\n","\"\n").replace("\\\\n"," ").replace("\\n","\n").replace("(b'","").replace("', b'')","").replace("\\x","\\\\x"))
                        if export:
                            if not os.path.isdir(os.path.join(pcaproot, str(pcapfile).replace(".pcap","").replace(".gzip",""))):
                                os.mkdir(os.path.join(pcaproot, str(pcapfile).replace(".pcap","").replace(".gzip","")))
                            else:
                                pass
                            objectselected = input("        Which object types would you like to extract from '{}' ?\n         dicom   http   smb   tftp   all ".format(os.path.join(pcaproot, pcapfile)))
                            if objectselected != "dicom" and objectselected != "http" and objectselected != "smb" and objectselected != "tftp" and objectselected != "all":
                                print("        You have not selected a valid option.\n        Please try again.")
                                sys.exit()
                            elif objectselected == "all":
                                for eachdir in objectlist:
                                    if not os.path.isdir(os.path.join(pcaproot, str(pcapfile).replace(".pcap","").replace(".gzip",""))+"/"+eachdir):
                                        os.mkdir(os.path.join(pcaproot, str(pcapfile).replace(".pcap","").replace(".gzip",""))+"/"+eachdir)
                                    else:
                                        pass
                                    subprocess.Popen(["tshark", "-r", pcapfile, "--ex", eachdir+","+str(os.path.join(pcaproot, str(pcapfile).replace(".pcap","").replace(".gzip","")))+"/"+eachdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
                            else:
                                subprocess.Popen(["tshark", "-r", pcapfile, "--ex", objectselected.strip()+","+str(os.path.join(pcaproot, str(pcapfile).replace(".pcap","").replace(".gzip","")))+"/"+objectselected], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
                        else:
                            pass
                        print("       Done.")
                    else:
                        pass
            except PermissionError:
                print("    '{}' could not be opened for processing due to a permissions error.".format(pcapfile))
            except:
                print("    '{}' could not be opened for processing due to an unknown error.".format(pcapfile))
    print("\n\n")

if __name__ == '__main__':
	main()
