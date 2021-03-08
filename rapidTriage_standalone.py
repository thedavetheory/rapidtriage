# RapidTriage.py
# Version: 1.2 - standalone version
# Trenton Bond - trent.bond@gmail.com
# 02-14-2014
#
# Standalone Notes:
#   -Designed to work with python3
#   -Designed to be compiled into a windows exe
#   -Automate output based on OS name and timestamp
#   -Modified by David Sullivan on 03/08/2021
#
# Description:
#   This script is meant to provide a framework for incident handlers
#   and system administrators to quickly gather incident discovery data for
#   Windows, FreeBSD, OSX, and Linux systems into the user specified <filename>.
#   The script has been organized so that commands or log files used to collect the
#   information can be easily modified or removed as necessary. The script also
#   allows the user to select sections to be chosen at runtime. Finally, if necessary, the
#   the results file can be hashed "<filename>-hash" to help ensure the integrity of the
#   results file.
#
#

import subprocess, time, os, datetime

# Create Output file name
outfile = (os.environ.get('USERNAME') + '_' + datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S') + '_' +
           os.getenv('COMPUTERNAME') + '_rapidTriage.txt')

# Open the user specified outfile
outputfile = open(outfile, "a")


# Reporting
# Timestamp Function - Provide a timestamp when necessary
def timestamp():
    now = str("[" + time.strftime("%H:%M:%S") + "]")
    return now


# Process Commands Function - Execute given commands and write the results to the user specified outfile
def run_cmds(list_cmds):
    for cmd in list_cmds:
        split_cmd = cmd.split("::")
        outputfile.write("\n")
        outputfile.write(timestamp() + "\t" + split_cmd[0] + ":\n")
        outputfile.write("===========================================================\n\n")
        p = subprocess.Popen(split_cmd[1], stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
        for line in p.stdout.readlines():
            outputfile.write("\t" + line.decode())


# Collection Engine

# Collect general system information based on identified operating system type
print("\nGathering General System Information...")
outputfile.write("""
############################################## 
#
#	General System Information	     
#
##############################################""")

outputfile.write("\n")
outputfile.write("\tSystem Time:\t" + time.asctime() + "\n")

# The format is <Description::Command> and both are required. Note the double colon "::" is the separator.
cmds = [
    'System Name::hostname',
    'Effective User::whoami',
    'System Type::for /F "delims== tokens=1-2" %a in (\'wmic os get Caption /format:list^|find "Caption"\') do @echo %b'
]

# Though we have a definition to execute the given commands, the format for the results in the "General System Information"
# are different from the other sections and thus required the execution for the above commands to be done here.
for cmd in cmds:
    split_cmd = cmd.split("::")
    outputfile.write("\t" + split_cmd[0] + ":\t")
    p = subprocess.Popen(split_cmd[1], stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
    outputfile.write(p.stdout.read().decode())
outputfile.write("\n")

# Windows General System  Related Commands
#
# This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
#
#   |	|	|
#   V	V	V
#
cmds = [
    'Filesystem Disk Space Usage::wmic logicaldisk get caption, size, freespace',
    'Memory Usage::wmic os get totalvisiblememorysize, freephysicalmemory,totalvirtualmemorysize, freevirtualmemory/format:list',
    'Load Average::wmic path win32_processor get deviceid, loadpercentage',
    'Enviroment Variables::set'
]

# Again the format for the results of these commands are different than the rest of the program. This requires the execution of the commands here.
for cmd in cmds:
    split_cmd = cmd.split("::")
    outputfile.write("\t" + split_cmd[0] + ":\n")
    outputfile.write("\t=========================\n\n")
    p = subprocess.Popen(split_cmd[1], stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
    for line in p.stdout.readlines():
        outputfile.write("\t" + line.decode())
    outputfile.write("\n")
outputfile.write("\n")

# Collect network information
print("Gathering Network Information...")
outputfile.write("""
############################################## 
#
#	Network Information		     
#
##############################################""")

# Windows Network Related Commands
#
# This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
#
#   |	|	|
#   V	V	V
#
cmds = [
    'Network Interface Configuration::ipconfig /all',
    'Route Table::route print',
    'Firewall Configuration::netsh advfirewall firewall show rule all',
    'ARP Table::arp -a',
    'Listening Ports::netstat -ano |find /i "listening"',
    'Established Connections::netstat -ano |find /i "established"',
    'Active/Listening Connections and Associated Command::netstat -anob',
    'Count of Half Open Connections::netstat -ano |find /i /c "syn_received"',
    'Count of Open Connections::netstat -ano |find /i /c "established"',
    '/etc/hosts Contents::type %SystemRoot%\System32\Drivers\etc\hosts',
    'Sessions Open to Other Systems::net use',
    'Local File Shares::net view \\\\127.0.0.1',
    'Available Local Shares::net share',
    'Open Sessions with Local Machine::net session'
]

run_cmds(cmds)
outputfile.write("\n")

# Collect process and service information
print("Gathering Process and Service Information...")
outputfile.write("""""
##############################################
#
# Process, Service, and Module Information	
#
##############################################""")

# Windows Process, Service, or Kernel Module  Related Commands
#
# This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
#
#   |	|	|
#   V	V	V
#
cmds = [
    'Running Processes::tasklist',
    'Process - Full Information::wmic process list full',
    'Services and Their State::sc query',
    'PIDs mapped to Services::tasklist /svc',
    'Intsalled Patches and Service Packs::wmic qfe'
]

run_cmds(cmds)
outputfile.write("\n")

# Collect scheduled task information
print("Gathering Scheduled Task Information...")
outputfile.write("""
############################################## 
#
#	Scheduled Task Information		
#
##############################################""")

# Windows Task Related Commands
#
# This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
#
#   |	|	|
#   V	V	V
#
cmds = [
    'Scheduled Tasks::schtasks',
    'Startup Items::wmic startup list full'
]

run_cmds(cmds)
outputfile.write("\n")

# Collect user information
print("Gathering Account and User Information...")
outputfile.write("""
############################################## 
#
#	Account and User Information		
#
##############################################""")

# Windows Account Related Commands
#
# This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
#
#   |	|	|
#   V	V	V
#
cmds = [
    'Local Accounts and Security Settings::wmic useraccount',
    'Accounts in the Local Administrators Group::net localgroup administrators'
]

run_cmds(cmds)
outputfile.write("\n")

# Collect log and history information
print("Gathering History Files and Log Data...")
outputfile.write("""
############################################## 
#
#	History Files and Log Data	     
#
##############################################""")

# Windows Log Files
#
# This list can easily be modified to include the locations of other log files.
# A list of available Windows log files can be found with "wevtutil el".
#
#   |	|	|
#   V	V	V
#

outputfile.write(timestamp() + "\tLast 100 Events from Log Files:\n")
outputfile.write("===========================================================\n\n")
log_files = [
    'Security',
    'Application',
    'System'
]
for file in log_files:
    outputfile.write("\n Log File - " + file + "\n")
    r = subprocess.Popen('wevtutil qe ' + file + ' /rd:true /c:100 /e:Events /f:text', stderr=subprocess.STDOUT,
                         stdout=subprocess.PIPE, shell=True)
    for line in r.stdout.readlines():
        outputfile.write("\t" + line.decode())
outputfile.write("\n")

# Close the user specified outfile
outputfile.close()
