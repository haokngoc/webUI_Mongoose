/*
 * settings.cpp
 *
 *  Created on: Jul 1, 2024
 *      Author: haonqptit
 */
#include "settings.h"
int Settings::switchToAPMode() {
	// 1. Modify the file content
	std::string filename = "/etc/NetworkManager/conf.d/99-unmanaged-devices.conf";

	std::ofstream file(filename, std::ios::trunc); // Open file for writing and truncate existing content

	if (!file.is_open()) {
		std::cerr << "Unable to open file!" << std::endl;
		return 1;
	}

	// Write new content to the file
	file << "[keyfile]\n"
		 << "unmanaged-devices=interface-name:wlan0\n";

	file.close(); // Close the file

	// 2. Reload NetworkManager
	std::system("systemctl reload NetworkManager");

	sleep(1);
//    std::system("reboot");
	// 3. Restart hostapd service
	std::system("systemctl restart hostapd");
	sleep(1);

	std::system("ip addr add 192.168.10.1/24 dev wlan0");

	return 0;
}
int Settings::switchToSTAMode() {
    // 1. Stop hostapd service
    std::system("systemctl stop hostapd");

    // 2. Modify the file content
    std::string filename = "/etc/NetworkManager/conf.d/99-unmanaged-devices.conf";
    std::ofstream file(filename, std::ios::trunc); // Open file for writing and truncate existing content

    if (!file.is_open()) {
        std::cerr << "Unable to open file!" << std::endl;
        return 1;
    }

    // Write new content to the file
    file << "[keyfile]\n"
         << "#unmanaged-devices=interface-name:wlan0\n";

    file.close(); // Close the file

    // 3. Reload NetworkManager
    std::system("systemctl reload NetworkManager");

    return 0;
}



