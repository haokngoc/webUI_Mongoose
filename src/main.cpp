#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <json-c/json.h>
#include "settings.h"
#include "mongoose.h"

#define FILE_NAME_JSON "/home/root/data.json"
#define FILE_NAME_LOGIN "/home/root/login.html"
#define FILE_NAME_SETTINGS "/home/root/settings.html"
#define FILE_NAME_HOME "/home/root/home.html"

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
int update_json_data(const char *ip_address, const char *logging_level, const char *wireless_mode, const char *wireless_SSID, const char *wireless_passphrase) {
    const char *json_file_name = FILE_NAME_JSON;
    FILE *fp = fopen(json_file_name,"r");
    if (!fp) {
        fprintf(stderr, "Cannot open file: %s\n", json_file_name);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *json_str = (char *)malloc(file_size + 1);
    fread(json_str, 1, file_size, fp);
    fclose(fp);

    // Parse JSON string to JSON object
    struct json_object *json_obj = json_tokener_parse(json_str);

    if (!json_obj) {
        fprintf(stderr, "Error parsing JSON.\n");
        free(json_str);
        return 1;
    }

    // Update values in JSON object
    struct json_object *settings_obj;
    if (!json_object_object_get_ex(json_obj, "settings", &settings_obj)) {
        fprintf(stderr, "No 'settings' object in JSON.\n");
        json_object_put(json_obj);
        free(json_str);
        return 1;
    }

    json_object_object_add(settings_obj, "ip-address", json_object_new_string(ip_address));
    json_object_object_add(settings_obj, "logging-level", json_object_new_string(logging_level));
    json_object_object_add(settings_obj, "wireless-mode", json_object_new_string(wireless_mode));
    json_object_object_add(settings_obj, "wireless-SSID", json_object_new_string(wireless_SSID));
    json_object_object_add(settings_obj, "wireless-Pass-Phrase", json_object_new_string(wireless_passphrase));

    // Write JSON object back to file
    fp = fopen(json_file_name, "w");
    if (!fp) {
        fprintf(stderr, "Cannot open file for writing: %s\n", json_file_name);
        json_object_put(json_obj);
        free(json_str);
        return 1;
    }

    const char *updated_json_str = json_object_to_json_string(json_obj);
    fprintf(fp, "%s\n", updated_json_str);

    fclose(fp);
    json_object_put(json_obj);
    free(json_str);

    return 0;
}
int compare_username_password(const char *username, const char *password) {
    const char *json_file_name = FILE_NAME_JSON;
    FILE *fp = fopen(json_file_name, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open file: %s\n", json_file_name);
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
        fprintf(stderr, "Error parsing JSON.\n");
        free(json_str);
        return 1;
    }

    struct json_object *account_info;
    if (!json_object_object_get_ex(json_obj, "account_information", &account_info)) {
        fprintf(stderr, "No 'account_information' object in JSON.\n");
        json_object_put(json_obj);
        free(json_str);
        return 1;
    }

    struct json_object *username_obj, *password_obj;
    if (!json_object_object_get_ex(account_info, "username", &username_obj) ||
        !json_object_object_get_ex(account_info, "password", &password_obj)) {
        fprintf(stderr, "Error getting username/password from JSON.\n");
        json_object_put(json_obj);
        free(json_str);
        return 1;
    }

    const char *username_file = json_object_get_string(username_obj);
    const char *password_file = json_object_get_string(password_obj);
    printf("%s %s\n", username_file, password_file);
    printf("%s %s\n", username, password);
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

// Event handler for HTTP connection
static void cb(struct mg_connection *c, int ev, void *ev_data) {
	Settings settings;
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *)ev_data;
        printf("Received request for: %.*s\n", (int)hm->uri.len, hm->uri.ptr);

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
        } else if(mg_http_match_uri(hm, "/settings")) {
        	struct mg_http_serve_opts opts = {0};
			opts.root_dir = s_root_dir;
			mg_http_serve_file(c, hm, FILE_NAME_SETTINGS, &opts);
        } else if (mg_http_match_uri(hm, "/update")) {
            // Handle /update
        	char ip_address[100], logging_level[100], wireless_mode[100], wireless_SSID[100], wireless_passphrase[100];
        	 // Parse form data
			mg_http_get_var(&hm->body, "ip-address", ip_address, sizeof(ip_address));
			mg_http_get_var(&hm->body, "logging-level", logging_level, sizeof(logging_level));
			mg_http_get_var(&hm->body, "wireless-mode", wireless_mode, sizeof(wireless_mode));
			mg_http_get_var(&hm->body, "wireless-SSID", wireless_SSID, sizeof(wireless_SSID));
			mg_http_get_var(&hm->body, "wireless-Pass-Phrase", wireless_passphrase, sizeof(wireless_passphrase));
			// update JSON data
			printf("%s\n\n",wireless_mode);
			if(update_json_data(ip_address, logging_level, wireless_mode, wireless_SSID, wireless_passphrase) == 0) {
				if(strcmp(wireless_mode,"station") == 0) {
					// handle station
					int res = settings.switchToSTAMode();
					if(res == 0) {
						printf("Switch successfully to STA mode\n");
					}
					else {
						printf("Fail\n");
					}

				}
				else {
					// handle access-mode
					int res = settings.switchToAPMode();
					if(res ==0) {
						printf("Switch successfully to AP mode\n");
					}
					else {
						printf("Fail\n");
					}
				}
				struct mg_http_serve_opts opts = {0};
				opts.root_dir = s_root_dir;
				mg_http_serve_file(c, hm, FILE_NAME_SETTINGS, &opts);

			} else {
				mg_http_reply(c, 500, "", "Error updating data.");
			}


        } else if (mg_http_match_uri(hm, "/change_password")) {
            // Handle /change_password
        } else if (mg_http_match_uri(hm, "/upload")) {
            // Handle /upload
        } else if (mg_http_match_uri(hm, "/download")) {
            // Handle /download
        } else {
            struct mg_http_serve_opts opts = {0};
            opts.root_dir = s_root_dir;
            opts.ssi_pattern = s_ssi_pattern;
            mg_http_serve_dir(c, hm, &opts);
        }
        MG_INFO(("%.*s %.*s %lu -> %.*s %lu", hm->method.len, hm->method.ptr,
                 hm->uri.len, hm->uri.ptr, hm->body.len, 3, c->send.buf + 9,
                 c->send.len));
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
        MG_ERROR(("Cannot listen on %s. Use http://ADDR:PORT or :PORT", s_listening_address));
        exit(EXIT_FAILURE);
    }
    if (mg_casecmp(s_enable_hexdump, "yes") == 0) c->is_hexdumping = 1;

    MG_INFO(("Mongoose version : v%s", MG_VERSION));
    MG_INFO(("Listening on     : %s", s_listening_address));
    MG_INFO(("Web root         : [%s]", s_root_dir));
    MG_INFO(("Upload dir       : [%s]", s_upload_dir ? s_upload_dir : "unset"));
    while (s_signo == 0) mg_mgr_poll(&mgr, 1000);
    mg_mgr_free(&mgr);
    MG_INFO(("Exiting on signal %d", s_signo));
    return 0;
}
