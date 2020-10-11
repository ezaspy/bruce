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
                    for packet in rdpcap(pcapfile):
                        pcap_trap = io.StringIO()
                        sys.stdout = pcap_trap
                        print(packet.show())
                        sys.stdout, processed_pcapfile, pcap = sys.__stdout__, str(pcap_trap.getvalue()), {}
                        pkt = str(re.sub(r"\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|len(=\d+\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|)chksum(=0x[A-Fa-f\d]+\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|)", r"||||||||||||||||||||LEN\1CHKSUM\2", str(re.sub(r"###\[[^\]]+\]###\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|\|", r"", str(re.sub(r"src(=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", r"srcip\1", str(re.sub(r"dst(=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", r"dstip\1", str(re.sub(r"src(=[A-Fa-f\d]{2}\:[A-Fa-f\d]{2}\:[A-Fa-f\d]{2}\:[A-Fa-f\d]{2}\:[A-Fa-f\d]{2}\:[A-Fa-f\d]{2})", r"srcmac\1", str(re.sub(r"dst(=[A-Fa-f\d]{2}\:[A-Fa-f\d]{2}\:[A-Fa-f\d]{2}\:[A-Fa-f\d]{2}\:[A-Fa-f\d]{2}\:[A-Fa-f\d]{2})", r"dstmac\1", str(processed_pcapfile.replace("\\n", "").replace("\n", "|||||||||||||||||||| ").replace("  ", "").replace(" = ","=").replace("= ","=").replace(" =","=").replace(" |||||||||||||||||||| ","||||||||||||||||||||").replace("|||||||||||||||||||| ","||||||||||||||||||||").replace(" ||||||||||||||||||||","||||||||||||||||||||").replace(" ","").replace("'","").replace("\\x","0x").replace("\\","").replace("||||||||||||||||||||load=","||||||||||||||||||||payload_hex="))[0:-7]))))))))))))
                        if "payload" in pkt:
                            pkt = pkt+"||||||||||||||||||||payload="+pkt.split("||||||||||||||||||||payload_hex=")[1]
                        else:
                            pass
                        for segment in pkt.split("||||||||||||||||||||"):
                            if "=" in segment and segment != "None" and len(segment) > 0:
                                pcap[str(segment.strip().replace("|","").split("=")[0]).replace("|","")] = str(segment.strip().replace("|","").split("=")[1]).replace("0x","")
                            else:
                                pass
                        for k, v in pcap.items():
                            if k == "payload":
                                try: # for i in range(0, len(data), 2) iterates over every second position in data: 0, 2, 4 etc.; data[i:i+2] looks at every pair of hex digits '43', '7c', etc.; chr(int(..., 16))
                                    v = re.sub(r"[^A-Fa-f\d]", r"", str(''.join(chr(int(v[i:i+2], 16)) for i in range(0, len(v), 2))).replace("\n","").lower())
                                except:
                                    pass
                            else:
                                pass
                            if len(v) > 0:
                                jsondict[k] = v
                            else:
                                pass
                        if len(jsondict) > 0:
                            jsonlist.append(json.dumps(jsondict))
                            jsondict.clear()
                        else:
                            pass
                    with open(os.path.join(pcaproot, pcapfile+".json"), "a") as pcapjson:
                        pcapjson.write(str(jsonlist).replace("'{","{").replace("}'","}").replace("'[","[").replace("]'","]").replace("\\\\n","").replace("\\\\","\\"))
                    print("       Done.")
                else:
                    pass
    print("\n\n")

if __name__ == '__main__':
	main()
