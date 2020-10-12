#!/usr/bin/env python3 -tt
import argparse, sys, os, shutil, io, time, re, json, subprocess
from contextlib import redirect_stdout
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("directory", nargs="+", help="Source directory where the packet capture files are located")

args = parser.parse_args()
directory = args.directory
d = directory[0]

def main():
    subprocess.Popen(["clear"])
    time.sleep(0.2)
    print("\n\n\n      _______________________________     _________         .    .\n     /                               \\   (..       \\_    ,  |\\  /|\n     |  Fish are friends, not food.   \\   \\       O  \\  /|  \\ \\/ /\n     \\_______________________________  \\   \\______    \\/ |   \\  /\n                                     \\__\\     vvvv\\    \\ |   /  |\n                                              \\^^^^  ==   \\_/   |\n                                               `\\_   ===    \\.  |\n                                               / /\\_   \\ /      |\n                                               |/   \\_  \\|      /\n                                                      \\________/\n\n") # https://www.asciiart.eu/animals/fish
    time.sleep(2)
    for pcaproot, _, files in os.walk(d):
        for pcapfile in files:
            with open(os.path.join(pcaproot, pcapfile), "rb") as pcapcontent:
                jsonlist, jsondict = [], {}
                if str(pcapcontent.readline())[2:42] == "\\xd4\\xc3\\xb2\\xa1\\x02\\x00\\x04\\x00\\x00\\x00":
                    print("      Processing {}...".format(pcapfile))
                    pcapcontent = re.sub(r"(\\n)\s*(\d+)", r"\1____________________\2", str(subprocess.Popen(["tshark", "-r", pcapfile, "-t", "ad"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()))
                    for packet in pcapcontent.split("\\n____________________"):
                        eachpkt = str(str(packet).replace("(b'","").replace("\\n', b'')","").replace("\\xe2\\x86\\x92 ","").replace("   "," ").replace("  "," ").strip())
                        for eachkv in re.findall(r"(?P<PacketID>\d+)\s+(?P<DateTime>\d{4}-\d{2}-\d{2}\s\d+:\d+:\d+\.\d+)\s+(?P<SourceIP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?P<DestinationIP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?P<Protocol>\w+)\s+(?P<PacketSize>\d+)\s+(?P<Payload>[\S\s]+)", eachpkt):
                            kv = list(eachkv)
                            if len(kv) > 1:
                                jsondict["PacketID"], jsondict["DateTime"], jsondict["SourceIP"], jsondict["DestinationIP"], jsondict["Protocol"], jsondict["PacketSize"], jsondict["Payload"] = kv[0], kv[1], kv[2], kv[3], kv[4], kv[5], kv[6]
                            else:
                                pass
                            jsonlist.append(json.dumps(jsondict))
                        jsondict.clear()
                    with open(os.path.join(pcaproot, pcapfile+".json"), "a") as pcapjson:
                        if len(jsonlist) > 0:
                            pcapjson.write(str(jsonlist).replace("'{","{").replace("}'","}").replace("'[","[").replace("]'","]").replace("\\\\n","").replace("\\\\\\\\","\\").replace("\\\\\\","\\").replace("\\\\","\\").replace("\\'","'").replace("\\)",")"))
                        else:
                            pass
                    print("       Done.")
                else:
                    pass
    print("\n\n")

if __name__ == '__main__':
	main()
