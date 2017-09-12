#! /usr/bin/env python

import nmap
import time
import socket
import json
import sys
import os
import requests
import itertools
import ConfigParser
from collections import OrderedDict
from ConfigParser import RawConfigParser

# Scan you local network for all hosts
def scan():

  hosts= str(get_lan_ip()) + "/24"
  nmap_args = "-sn" #simple host discovery without portscan

  scanner = nmap.PortScanner()
  scanner.scan(hosts=hosts, arguments=nmap_args)

  hostList = []

  for ip in scanner.all_hosts():

    host = {"ip" : ip}
    #print scanner[ip]
    if "hostnames" in scanner[ip]:
      host["hostnames"] = scanner[ip]["hostnames"][0]["name"]
      #print "test"
      #print host["name"]

    if "mac" in scanner[ip]["addresses"]:
      host["mac"] = scanner[ip]["addresses"]["mac"].upper()

    if "ipv4" in scanner[ip]["addresses"]:
      host["ipv4"] = scanner[ip]["addresses"]["ipv4"].upper()
    #print host["hostnames"] + ": [" + host["mac"]
    hostList.append(host)

  return hostList


# Get your local network IP address. e.g. 192.168.178.X
def get_lan_ip():

  try:
    return ([(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1])
  except socket.error as e:
    sys.stderr.write(str(e) + "\n") # probably offline / no internet connection
    sys.exit(e.errno)


# Build the chat message being send to telegram
def notifytelegram(newUsersShort, newUsers, leftUsers, existingUsers, unkownhost, offlineusers):
  messageT = "- - - - - - - - - - - - - -\n"

  if len(newUsers) > 0:
    messageT += "JOINED:"
    messageT += ", ".join(newUsersShort)
    messageT += "\n\n"

  if len(leftUsers) > 0:
    messageT += "LEFT:"
    messageT += ", ".join(leftUsers)
    messageT += "\n\n"

  if len(unkownhost) > 0:
    messageT+= "UNKNOWN:\n"
    messageT += "\n".join(unkownhost)
    messageT += "\n\n"

  if len(existingUsers) > 0:
    messageT += "ONLINE:\n"
    messageT += ", ".join(existingUsers)
    messageT += "\n\n"

  if len(offlineusers) > 0:
    messageT += "OFFLINE:\n"
    messageT += ", ".join(offlineusers)
    messageT += "\n\n"

  else:
    messageT += "."
  
  sendtelegramRequest(messageT)


# Send the HTTP Post Request to telegram
def sendtelegramRequest(messageT):
   requests.get(telegramConfig["weburl"]+messageT+"&chat_id="+telegramConfig["chatid"])  


   
   
# Read the config file
def parseConfigFile():

  scriptDir = os.path.dirname(os.path.realpath(__file__))
  configDir = os.path.join(scriptDir, "config.json")

  jsonFile = open(configDir)
  config = json.load(jsonFile)

  if len(config) < 1:
    sys.stderr.write("Oops, couldn't read the config file. Consult the readme.\n")
    sys.exit(0)

  try:
    telegramConfig = config["telegram"]
    known_hosts = dict()
    hoststohideifoffline = config["hideifoffline"]
    #print telegramConfig["weburl"]
    #print hoststohideifoffline
	
    for hostname, macs in config["hosts"].iteritems():
      known_hosts[hostname] = [mac.upper() for mac in macs]

  except KeyError as e:
    sys.stderr.write("Please correct your config file. Missing section %s .\n" %str(e))
    sys.exit(0)

  if len(known_hosts) == 0:
    sys.stderr.write("Oops, you did not specify any known hosts. Please correct your config file.\n")
    sys.exit(0)

  if not "weburl" in telegramConfig or telegramConfig["weburl"] is None:
    sys.stderr.write("Oops, you did not set up the Telegram integration. Please correct your config file.\n")
    sys.exit(0)

  return telegramConfig, known_hosts, hoststohideifoffline


# Entry point
if __name__ == "__main__":

  telegramConfig, KNOWN_HOSTS, hoststohideifoffline = parseConfigFile()

  # Initialize. Noone is here yet
  activeHosts = set()
  activeHostsFull = set()
  
  while True:
    resultset = set()
    resultset = scan()
    scannedHosts = [host["mac"] for host in resultset if "mac" in host]
    scannedHostnames = [host["hostnames"] for host in resultset if "hostnames" in host]
    scannedIPs = [host["ipv4"] for host in resultset if "ipv4" in host]
    #print "scannedhosts", scannedHosts
    #print " "
    #print "Hostnames", scannedHostnames
    #print " "
    #print "scannedip", scannedIPs 


    recognizedHosts = set()
    allHosts = set()
    onlinehs = set()
    recognizedHostsFull = set()
    unrecognizedHosts = set()
    hideofflinehostsset=set()
    allknownmac=""
	
    #print hoststohideifoffline
	
    hideofflinehosts = json.dumps(hoststohideifoffline)
    #hideofflinehosts = json.dumps(hoststohideifoffline)
    #hideofflinehosts = json.loads(hideofflinehosts)
	
    #print "hideoffline :", hideofflinehosts

    for hostname, macs in KNOWN_HOSTS.items():
       #print macs
       if hostname in hideofflinehosts:
           hideofflinehostsset.add(hostname)
           #print hostname, hideofflinehosts
	
	
    for hostname, macs in KNOWN_HOSTS.items():
       #print macs
       allknownmac += macs[0]+ ", "
       allHosts.add(hostname)
	   
    #print allmac
	
    for hostname, macs in KNOWN_HOSTS.iteritems():

      #print "known ", macs
      inti=0
      for scannedHost in scannedHosts:

        #print scannedHost
        #print macs
        #print hostname
        #print "+++++++++"
        
        if scannedHost in macs:
          recognizedHosts.add(hostname)
          recognizedHostsFull.add("Hostname:"+ hostname+"  MAC:"+ scannedHost+"  IP:"+ scannedIPs[inti]+ "  Name:"+ scannedHostnames[inti])

        if scannedHost not in allknownmac:
	      unrecognizedHosts.add("MAC:"+ scannedHost+"  IP:"+ scannedIPs[inti]+ "  Name:"+ scannedHostnames[inti])
        inti += 1


    # print "recognizedHosts", recognizedHosts
    # print "unrecognizedHosts", unrecognizedHosts
    # recognizedHosts = set([KNOWN_HOSTS[host] for host in scannedHosts if host in KNOWN_HOSTS])

    # who joined the network?
    newHosts = recognizedHosts - activeHosts
    newHostsFull = recognizedHostsFull - activeHostsFull

    # who left the network?
    leftHosts = activeHosts - recognizedHosts
    leftHostsFull = activeHostsFull - recognizedHostsFull
	
	#who is offline
    offlineHosts = allHosts - recognizedHosts
    offlineHosts = offlineHosts - hideofflinehostsset
    #print "QQQQQQ offline",offlineHosts
	
	
    print "----------------------------------"
    print "left",leftHosts
    print "joined", newHosts
    print "activeHosts", activeHosts
    #print "recognizedHosts", recognizedHosts
    print "unrecognizedHosts", unrecognizedHosts
    print " "
    onlinehs = activeHosts - leftHosts
    onlinehs = onlinehs  |newHosts
    print onlinehs
    # announce the new and leaving users in telegram
    #if len(newHosts) > 0 or len(leftHosts) > 0:
    notifytelegram(sorted(newHosts), sorted(newHostsFull), sorted(leftHosts), sorted(onlinehs), sorted(unrecognizedHosts), sorted(offlineHosts))

    # remember everyone for the next scan
    activeHosts = recognizedHosts
    activeHostsFull = recognizedHostsFull

    # wait 60 seconds before trying again
    time.sleep(300)