/*
 * settings.h
 *
 *  Created on: Jul 1, 2024
 *      Author: Haonqptit
 */
#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <fstream>
#ifndef SETTINGS_H_
#define SETTINGS_H_


class Settings {
private:
    std::string ip_address;
    std::string logging_method;
    std::string logging_level;
    std::string wireless_mode;
    std::string wireless_ssid;
    std::string wireless_pass_phrase;

public:
    int switchToSTAMode();
    int switchToAPMode();

	const std::string& getIpAddress() const {
		return ip_address;
	}

	void setIpAddress(const std::string &ipAddress) {
		ip_address = ipAddress;
	}

	const std::string& getLoggingLevel() const {
		return logging_level;
	}

	void setLoggingLevel(const std::string &loggingLevel) {
		logging_level = loggingLevel;
	}

	const std::string& getLoggingMethod() const {
		return logging_method;
	}

	void setLoggingMethod(const std::string &loggingMethod) {
		logging_method = loggingMethod;
	}

	const std::string& getWirelessMode() const {
		return wireless_mode;
	}

	void setWirelessMode(const std::string &wirelessMode) {
		wireless_mode = wirelessMode;
	}

	const std::string& getWirelessPassPhrase() const {
		return wireless_pass_phrase;
	}

	void setWirelessPassPhrase(const std::string &wirelessPassPhrase) {
		wireless_pass_phrase = wirelessPassPhrase;
	}

	const std::string& getWirelessSsid() const {
		return wireless_ssid;
	}

	void setWirelessSsid(const std::string &wirelessSsid) {
		wireless_ssid = wirelessSsid;
	}
};



#endif /* SETTINGS_H_ */
