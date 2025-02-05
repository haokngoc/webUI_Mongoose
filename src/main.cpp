#include <stdio.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <json-c/json.h>
#include "settings.h"
#include "mongoose.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include "JSONParser.h"

#define FILE_NAME_JSON "/home/root/data.json"
#define FILE_NAME_LOGIN "/home/root/login.html"
#define FILE_NAME_SETTINGS "/home/root/settings.html"
#define FILE_NAME_HOME "/home/root/home.html"
#define FILE_NAME_LOG "/home/root/file.txt"

#define FILE_NAME_INFOMATION "/home/root/information.json"

// Static variables
static int s_debug_level = MG_LL_INFO;
static const char *s_root_dir = "/home/root";
static const char *s_listening_address = "http://0.0.0.0:9000";
static const char *s_enable_hexdump = "no";
static const char *s_ssi_pattern = ".html";
static const char *s_upload_dir = "/home/root";
static int s_signo;

// Signal handler
static void signal_handler(int signo) {
    s_signo = signo;
}

int compare_username_password(const char *username, const char *password) {
    const char *json_file_name = FILE_NAME_JSON;
    FILE *fp = fopen(json_file_name, "r");
    if (!fp) {
        spdlog::error("Cannot open file: {}", json_file_name);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *json_str = (char *)malloc(file_size + 1);
    fread(json_str, 1, file_size, fp);
    fclose(fp);

    struct json_object *json_obj = json_tokener_parse(json_str);

    if (!json_obj) {
        spdlog::error("Error parsing JSON.");
        free(json_str);
        return 1;
    }

    struct json_object *account_info;
    if (!json_object_object_get_ex(json_obj, "account_information", &account_info)) {
        spdlog::error("No 'account_information' object in JSON.");
        json_object_put(json_obj);
        free(json_str);
        return 1;
    }

    struct json_object *username_obj, *password_obj;
    if (!json_object_object_get_ex(account_info, "username", &username_obj) ||
        !json_object_object_get_ex(account_info, "password", &password_obj)) {
        spdlog::error("Error getting username/password from JSON.");
        json_object_put(json_obj);
        free(json_str);
        return 1;
    }

    const char *username_file = json_object_get_string(username_obj);
    const char *password_file = json_object_get_string(password_obj);
    spdlog::info("Username from file: {}, Password from file: {}", username_file, password_file);
    spdlog::info("Username from input: {}, Password from input: {}", username, password);

    if (strcmp(username, username_file) == 0 && strcmp(password, password_file) == 0) {
        json_object_put(json_obj);
        free(json_str);
        return 0;
    } else {
        json_object_put(json_obj);
        free(json_str);
        return 1;
    }
}
void update_password_in_json(const char *new_password) {
    FILE *file = fopen(FILE_NAME_JSON, "r+");
    if (file == NULL) {
        spdlog::error("Failed to open data.json file");
        perror("Failed to open data.json file");
        return;
    }

    // Determine the size of the file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    // Read the content of the file into a buffer
    char *buffer = (char *)malloc(file_size + 1);
    if (buffer == NULL) {
        fclose(file);
        spdlog::error("Memory allocation failed");
        perror("Memory allocation failed");
        return;
    }
    fread(buffer, 1, file_size, file);
    buffer[file_size] = '\0';

    // Find the position of "password" in the JSON file
    char *password_start = strstr(buffer, "\"password\": \"");
    if (password_start != NULL) {
        password_start += strlen("\"password\": \"");
        char *password_end = strchr(password_start, '\"');
        if (password_end != NULL) {
            // Copy the new password into the old password's position
            strncpy(password_start, new_password, password_end - password_start);
        }
    } else {
        spdlog::error("Failed to find password field in JSON");
        printf("Failed to find password field in JSON\n");
    }

    // Set the file pointer to the beginning and rewrite the updated content
    rewind(file);
    fwrite(buffer, 1, file_size, file);

    // Free memory and close the file
    free(buffer);
    fclose(file);
}

// Event handler for HTTP connection
static void cb(struct mg_connection *c, int ev, void *ev_data) {
	Settings settings;
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *)ev_data;
        spdlog::info("Received request for: {}", std::string(hm->uri.ptr, hm->uri.len));
        char cwd[1024];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            std::cout << "Current working dir: " << cwd << std::endl;
        } else {
            std::cerr << "getcwd() error\n";
        }

        std::string filePath = std::string(cwd) + "/settings.html";

        if (mg_http_match_uri(hm, "/")) {
            struct mg_http_serve_opts opts = {0};
            mg_http_serve_file(c, hm, FILE_NAME_LOGIN, &opts);
        } else if (mg_http_match_uri(hm, "/login")) {
            char username[100], password[100];
            mg_http_get_var(&hm->body, "username", username, sizeof(username));
            mg_http_get_var(&hm->body, "password", password, sizeof(password));

            if (compare_username_password(username, password) == 0) {
                struct mg_http_serve_opts opts = {0};
                opts.root_dir = s_root_dir;
                mg_http_serve_file(c, hm, FILE_NAME_HOME, &opts);
            } else {
                mg_http_reply(c, 401, "", "Unauthorized");
            }
        } else if(mg_http_match_uri(hm, "/")) {
//        	struct mg_http_serve_opts opts = {0};
//			opts.root_dir = s_root_dir;
//			mg_http_serve_file(c, hm, FILE_NAME_SETTINGS, &opts);
        	std::ifstream htmlFile(filePath);
			if (htmlFile.is_open()) {
				std::stringstream buffer;
				buffer << htmlFile.rdbuf();
				std::string response = buffer.str();
				mg_http_reply(c, 200, "Content-Type: text/html\r\n", "%s", response.c_str());

			} else {
				std::cerr << "Error: Could not open " << filePath << std::endl;
				std::string response = "Error: Could not open settings.html";
				mg_http_reply(c, 500, "Content-Type: text/plain\r\n", "%s", response.c_str());
			}

        } else if (mg_http_match_uri(hm, "/update")) {
            // Handle /update
        	char ip_address[100], logging_level[100], wireless_mode[100], wireless_SSID[100], wireless_passphrase[100];
        	char ip_select[100], gateway[100], dns[100];
        	// Parse form data
			mg_http_get_var(&hm->body, "ip-address-manual", ip_address, sizeof(ip_address));
			mg_http_get_var(&hm->body, "logging-level", logging_level, sizeof(logging_level));
			mg_http_get_var(&hm->body, "wireless-mode", wireless_mode, sizeof(wireless_mode));
			mg_http_get_var(&hm->body, "wireless-SSID", wireless_SSID, sizeof(wireless_SSID));
			mg_http_get_var(&hm->body, "wireless-Pass-Phrase", wireless_passphrase, sizeof(wireless_passphrase));
			mg_http_get_var(&hm->body, "gateway-manual", gateway, sizeof(gateway));
			mg_http_get_var(&hm->body, "dns-manual", dns, sizeof(dns));
			mg_http_get_var(&hm->body, "ip-select", ip_select, sizeof(ip_select));
			// update JSON data
			spdlog::info("Wireless mode: {}", wireless_mode);
			spdlog::info("ip-select: {}",ip_select);
			std::cout << "mode " << wireless_mode << std::endl;

			std::cout << "select: " << ip_select << std::endl;

			if(strcmp(wireless_mode,"station") == 0) {

				settings.updateDataJsonSTA(ip_address,logging_level,wireless_mode,wireless_SSID,wireless_passphrase,ip_select);
				settings.switchToSTAMode(wireless_SSID,wireless_passphrase,ip_address,gateway,dns,ip_select);

			}
			else {
				settings.switchToAPMode();

			}
			struct mg_http_serve_opts opts = {0};
			opts.root_dir = s_root_dir;
			mg_http_serve_file(c, hm, FILE_NAME_SETTINGS, &opts);
        } else if (mg_http_match_uri(hm, "/change_password")) {

            // Handle /change_password
        	char password[100];
			// mg_http_get_var(&hm->body, "username", username, sizeof(username));
			mg_http_get_var(&hm->body, "new_password", password, sizeof(password));
			update_password_in_json(password);

			// Redirect to a success page or perform other actions if necessary
			mg_http_reply(c, 200, "", "<html><head><script>alert('Password changed successfully!'); window.location.href = 'change_password.html';</script></head><body></body></html>");
        } else if (mg_http_match_uri(hm, "/upload")) {
            // Handle /upload
        } else if (mg_http_match_uri(hm, "/download")) {
        	FILE *fp = fopen(FILE_NAME_LOG, "rb");
			if (fp != NULL) {
				fseek(fp, 0, SEEK_END);
				long file_size = ftell(fp);
				fseek(fp, 0, SEEK_SET);

				char *file_content = (char *)malloc(file_size);
				if (file_content != NULL) {
					fread(file_content, 1, file_size, fp);
					fclose(fp);

					mg_http_reply(c, 200, "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"logs.txt\"\r\n", "%.*s", (int)file_size, file_content);

					free(file_content);
				} else {
					fclose(fp);
					mg_http_reply(c, 500, "", "Error reading file.");
				}
			} else {
				mg_http_reply(c, 500, "", "Error opening file.");
			}

        } else {
            struct mg_http_serve_opts opts = {0};
            opts.root_dir = s_root_dir;
            opts.ssi_pattern = s_ssi_pattern;
            mg_http_serve_dir(c, hm, &opts);
        }
        spdlog::info("{} {} {} -> {} {}", std::string(hm->method.ptr, hm->method.len),
                     std::string(hm->uri.ptr, hm->uri.len), hm->body.len, 3, c->send.buf + 9,
                     c->send.len);
    }
}

// Usage function
static void usage(const char *prog) {
    fprintf(stderr,
            "Mongoose v.%s\n"
            "Usage: %s OPTIONS\n"
            "  -H yes|no - enable traffic hexdump, default: '%s'\n"
            "  -S PAT    - SSI filename pattern, default: '%s'\n"
            "  -d DIR    - directory to serve, default: '%s'\n"
            "  -l ADDR   - listening address, default: '%s'\n"
            "  -u DIR    - file upload directory, default: unset\n"
            "  -v LEVEL  - debug level, from 0 to 4, default: %d\n",
            MG_VERSION, prog, s_enable_hexdump, s_ssi_pattern, s_root_dir,
            s_listening_address, s_debug_level);
    exit(EXIT_FAILURE);
}




int main(int argc, char *argv[]) {
	Settings settings;
	int ret = settings.initializeJson();
	std::cout<< "ret: " << ret << std::endl;
	if(ret == 1) {
		settings.switchToAPMode();
	}

	auto file_logger = spdlog::basic_logger_mt("file_logger", FILE_NAME_LOG);
	spdlog::set_default_logger(file_logger);
	spdlog::set_level(spdlog::level::info); // Set global log level to info

//	auto console_logger = spdlog::stdout_color_mt("console");
//	spdlog::set_default_logger(console_logger);
//	spdlog::set_level(spdlog::level::info);



    char path[MG_PATH_MAX] = ".";
    struct mg_mgr mgr;
    struct mg_connection *c;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            s_root_dir = argv[++i];
        } else if (strcmp(argv[i], "-H") == 0) {
            s_enable_hexdump = argv[++i];
        } else if (strcmp(argv[i], "-S") == 0) {
            s_ssi_pattern = argv[++i];
        } else if (strcmp(argv[i], "-l") == 0) {
            s_listening_address = argv[++i];
        } else if (strcmp(argv[i], "-u") == 0) {
            s_upload_dir = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            s_debug_level = atoi(argv[++i]);
        } else {
            usage(argv[0]);
        }
    }

    if (strchr(s_root_dir, ',') == NULL) {
        realpath(s_root_dir, path);
        s_root_dir = path;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    mg_log_set(s_debug_level);
    mg_mgr_init(&mgr);
    if ((c = mg_http_listen(&mgr, s_listening_address, cb, &mgr)) == NULL) {
        spdlog::error("Cannot listen on {}. Use http://ADDR:PORT or :PORT", s_listening_address);
        exit(EXIT_FAILURE);
    }
    if (mg_casecmp(s_enable_hexdump, "yes") == 0) c->is_hexdumping = 1;

    spdlog::info("Mongoose version : v{}", MG_VERSION);
    spdlog::info("Listening on     : {}", s_listening_address);
    spdlog::info("Web root         : [{}]", s_root_dir);
    spdlog::info("Upload dir       : [{}]", s_upload_dir ? s_upload_dir : "unset");

    while (s_signo == 0) mg_mgr_poll(&mgr, 1000);

    mg_mgr_free(&mgr);
    spdlog::info("Exiting on signal {}", s_signo);
    spdlog::drop_all();
    return 0;

}
