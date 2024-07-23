/*
 * settings.cpp
 *
 *  Created on: Jul 1, 2024
 *      Author: haonqptit
 */
#include "settings.h"
#include "NetworkManagerWrapper.h"
#include <iostream>
#include <exception>
#define INFORMATION_FILE_NAME "/home/root/information.json"

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
	std::cout << "Switch to AP mode sucssesful";
	return 0;
}

int Settings::switchToSTAMode(const std::string& ssid, const std::string& password, const std::string& static_ip, const std::string& gateway, const std::string& dns, const std::string& mode) {
    // 1. Stop hostapd service
    int ret = std::system("systemctl stop hostapd");
    if (ret != 0) {
        std::cerr << "Failed to stop hostapd service. Error code: " << ret << std::endl;
        return ret;
    }

    // 2. Modify the file content
    std::string filename = "/etc/NetworkManager/conf.d/99-unmanaged-devices.conf";
    std::ofstream file(filename, std::ios::trunc); // Open file for writing and truncate existing content

    if (!file.is_open()) {
        std::cerr << "Unable to open file: " << filename << std::endl;
        return 1;
    }

    // Write new content to the file
    file << "[keyfile]\n"
         << "#unmanaged-devices=interface-name:wlan0\n";

    file.close(); // Close the file

    // 3. Reload NetworkManager
    ret = std::system("systemctl reload NetworkManager");
    if (ret != 0) {
        std::cerr << "Failed to reload NetworkManager. Error code: " << ret << std::endl;
        return ret;
    }
    sleep(5);

    // 4. Connect to WiFi using nmcli
//    std::string connectCommand = "nmcli dev wifi connect \"" + ssid + "\" password \"" + password + "\" ifname wlan0";
//    ret = std::system(connectCommand.c_str());
//    if (ret != 0) {
//        std::cerr << "Failed to connect to WiFi. Error code: " << ret << std::endl;
//        return ret;
//    }
    auto logger = spdlog::stdout_color_mt("nm_logger");
    if(mode == "auto") {
    	NetworkManagerWrapper nm_wrapper("wlan0", ssid, password, "", "", "", "MyConnection", logger);
		if (nm_wrapper.connectToAccessPointWithAutoIP()) {
			logger->info("Connected to access point with auto IP successfully.");
		} else {
			logger->error("Failed to connect to access point with auto IP.");
			return 1;
		}
    }
    else {
        NetworkManagerWrapper nm_wrapper("wlan0", ssid, password, static_ip, gateway, dns, "Myconnection", logger);
        // them truong gateway dns
        if (nm_wrapper.connectToAccessPointWithStaticIP()) {
            logger->info("Connected to access point with static IP successfully.");
        } else {
            logger->error("Failed to connect to access point with static IP.");
            return 1;
        }
    }
//
//	// Example of connecting to a WiFi access point
//	std::string wlan_device = "wlan0";
//
//	if (wifi_manager.connect_to_access_point(wlan_device, ssid, password)) {
//		std::cout << "Connected to " << ssid << std::endl;
//	} else {
//		std::cerr << "Failed to connect to " << ssid << std::endl;
//		return 1;
//	}

    std::cout << "Switch to STA mode sucssesful";

    return 0;

}
int Settings::initializeJson() {
	Information info = this->parser.parseInformation(INFORMATION_FILE_NAME);
	std::string configuration_file_name = info.getJsonPath();
	Configuration config = this->parser.parseConfiguration(configuration_file_name);
	// co thong tin cua congig roi, gio lay ra thoi

	std::string ap_status = config.getApStatus();
	std::string sta_status = config.getStaStatus();
	std::cout << "Status AP: " << ap_status << std::endl;
	std::cout << "Status STA: " << sta_status << std::endl;
	int res = 1;
	if(ap_status == "active") {
		 res = switchToAPMode();
	}
	if(sta_status == "active") {
//		res = switchToSTAMode(config.getStaWirelessSsid(), config.getStaWirelessPassPhrase());
	}
	return 0;
}
int Settings::updateDataJsonSTA(const std::string& ip_address, const std::string& logging_level,
		const std::string& wireless_mode, const std::string& wireless_SSID,
		const std::string& wireless_passphrase, const std::string& mode) {

	Information info = this->parser.parseInformation(INFORMATION_FILE_NAME);
	std::string configuration_file_name = info.getJsonPath();
	Configuration config = this->parser.parseConfiguration(configuration_file_name);
	config.setStaIpAddress(ip_address);
	config.setStaLoggingLevel(logging_level);
	config.setStaWirelessSsid(wireless_SSID);
	config.setStaWirelessMode(wireless_mode);
	config.setStaWirelessPassPhrase(wireless_passphrase);
	config.setStaStatus("active");
	config.setApStatus("deactive");
	if(mode == "auto") {
		config.setStaAuto("true");
	}
	else {
		config.setStaAuto("false");
	}
	this->parser.updateConfiguration(config, configuration_file_name);
//	int ret = switchToSTAMode(config.getStaWirelessSsid(), config.getStaWirelessPassPhrase());

	return 0;
}
int Settings::updateDataJsonAp() {
	Information info = this->parser.parseInformation(INFORMATION_FILE_NAME);
	std::string configuration_file_name = info.getJsonPath();
	Configuration config = this->parser.parseConfiguration(configuration_file_name);
	config.setApStatus("active");
	config.setStaStatus("deactive");
	this->parser.updateConfiguration(config, configuration_file_name);
	return 0;
}




