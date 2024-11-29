#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/common/exception.hpp"
#include "duckmail_fetch.hpp"
#include <curl/curl.h>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <future>
#include <mutex>
#include <iostream>
#include <duckdb/main/extension_util.hpp>

namespace duckdb {
    // Send an IMAP request and retrieve the response
    static std::string SendIMAPRequest(const std::string &url, const std::string &username, const std::string &password) {
        CURL *curl = curl_easy_init();
        if (!curl) {
            throw IOException("Failed to initialize cURL.");
        }

        std::string response;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
        curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL); // Enforce secure connection
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L); // Timeout after 30 seconds
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L); // Connection timeout
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
            auto &response = *(std::string *)userdata;
            response.append(ptr, size * nmemb);
            return size * nmemb;
        });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            curl_easy_cleanup(curl);
            throw IOException("cURL error: " + std::string(curl_easy_strerror(res)));
        }

        curl_easy_cleanup(curl);
        std::cout << "IMAP Request to " << url << " completed successfully.\n";
        return response;
    }

    // Fetch message IDs using IMAP
    std::vector<std::string> FetchIMAPMessageIDs(const std::string &server_url, const std::string &username,
                                                 const std::string &password, int64_t limit) {
        std::string url = "imaps://" + server_url + "/INBOX"; // Specify the mailbox
        std::cout << "Fetching message IDs from URL: " << url << "\n";

        std::string response = SendIMAPRequest(url, username, password);

        // Placeholder for IMAP-specific parsing logic to extract message IDs
        std::vector<std::string> message_ids;

        // Add mock parsing for demonstration purposes
        message_ids.push_back("1");
        message_ids.push_back("2");

        std::cout << "Fetched " << message_ids.size() << " message IDs.\n";
        return message_ids;
    }

std::map<std::string, std::string> FetchIMAPMessageDetails(const std::string &server_url,
                                                           const std::string &username,
                                                           const std::string &password,
                                                           const std::string &message_id) {
    std::cout << "Fetching details for message ID: " << message_id << " from server: " << server_url << "\n";

    // Construct the IMAP URL
    std::string url = "imaps://" + server_url + "/INBOX";

    // Initialize cURL
    CURL *curl = curl_easy_init();
    if (!curl) {
        throw IOException("Failed to initialize cURL.");
    }

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());

    // Construct the FETCH command and set it
    std::string fetch_command = "UID FETCH " + message_id + " (BODY.PEEK[])";
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, fetch_command.c_str());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
        auto &response = *(std::string *)userdata;
        response.append(ptr, size * nmemb);
        return size * nmemb;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "cURL error: " << curl_easy_strerror(res) << "\n";
        curl_easy_cleanup(curl);
        throw IOException("cURL error: " + std::string(curl_easy_strerror(res)));
    }

    curl_easy_cleanup(curl);

    // Debugging: Print the first part of the response
    std::cout << "Response for message ID " << message_id << ": " << response.substr(0, 500) << "\n";

    // Parse the IMAP response
    std::map<std::string, std::string> details;
    details["id"] = message_id;

    // Extract subject
    size_t subject_pos = response.find("Subject: ");
    if (subject_pos != std::string::npos) {
        size_t end_pos = response.find("\r\n", subject_pos);
        details["subject"] = response.substr(subject_pos + 9, end_pos - subject_pos - 9);
    } else {
        details["subject"] = "No subject found.";
    }

    // Extract body snippet
    size_t body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        size_t body_end = response.find("\r\n", body_start + 4); // Assume a single line for snippet
        details["snippet"] = response.substr(body_start + 4, body_end - body_start - 4);
    } else {
        details["snippet"] = "No snippet available.";
    }

    std::cout << "Fetched details for message ID " << message_id << ": Subject: " << details["subject"]
              << ", Snippet: " << details["snippet"] << "\n";

    return details;
}
    // Fetch all emails from the IMAP server
    std::vector<std::map<std::string, std::string>> FetchEmails(const std::string &server_url,
                                                                const std::string &username,
                                                                const std::string &password, int64_t limit) {
        auto message_ids = FetchIMAPMessageIDs(server_url, username, password, limit);
        if (message_ids.empty()) {
            std::cerr << "No message IDs retrieved. Exiting email fetch process.\n";
            return {};
        }

        std::cout << "Fetching email details for " << message_ids.size() << " message IDs.\n";
        std::vector<std::map<std::string, std::string>> email_details;
        for (const auto &id : message_ids) {
            auto details = FetchIMAPMessageDetails(server_url, username, password, id);
            email_details.push_back(details);
        }

        return email_details;
    }

    struct IMAPGlobalState : public GlobalTableFunctionState {
        std::vector<std::map<std::string, std::string> > emails;
        idx_t current_idx = 0;
        bool done = false;

        explicit IMAPGlobalState() = default;
    };

    struct IMAPBindData : public FunctionData {
        std::string username;
        std::string password;
        std::string server_url;
        int64_t limit;

        explicit IMAPBindData(std::string username_p, std::string password_p, std::string server_url_p, int64_t limit_p)
            : username(std::move(username_p)), password(std::move(password_p)), server_url(std::move(server_url_p)),
              limit(limit_p) {
        }

        unique_ptr<FunctionData> Copy() const override {
            return make_uniq<IMAPBindData>(username, password, server_url, limit);
        }

        bool Equals(const FunctionData &other) const override {
            auto &other_data = (const IMAPBindData &) other;
            return username == other_data.username && password == other_data.password &&
                   server_url == other_data.server_url && limit == other_data.limit;
        }
    };

    unique_ptr<FunctionData> IMAPBind(ClientContext &context, TableFunctionBindInput &input,
                                      vector<LogicalType> &return_types, vector<string> &names) {
        auto &secret_manager = SecretManager::Get(context);
        auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
        auto secret_match = secret_manager.LookupSecret(transaction, "imap", "imap");

        if (!secret_match.HasMatch()) {
            throw InvalidInputException("No 'imap' secret found. Please create a secret with 'CREATE SECRET' first.");
        }

        auto &secret = secret_match.GetSecret();
        if (secret.GetType() != "imap") {
            throw InvalidInputException("Invalid secret type. Expected 'imap', got '%s'", secret.GetType());
        }

        const auto *kv_secret = dynamic_cast<const KeyValueSecret *>(&secret);
        if (!kv_secret) {
            throw InvalidInputException("Invalid secret format for 'imap' secret.");
        }

        Value username, password, server_url;
        if (!kv_secret->TryGetValue("username", username)) {
            throw InvalidInputException("'username' not found in 'imap' secret.");
        }
        if (!kv_secret->TryGetValue("password", password)) {
            throw InvalidInputException("'password' not found in 'imap' secret.");
        }
        if (!kv_secret->TryGetValue("server", server_url)) {
            throw InvalidInputException("'server' not found in 'imap' secret.");
        }

        // Parse optional limit parameter
        int64_t limit = -1;
        if (input.named_parameters.find("mail_limit") != input.named_parameters.end()) {
            limit = input.named_parameters.at("mail_limit").GetValue<int64_t>();
        }

        // Set output schema
        return_types.emplace_back(LogicalType::VARCHAR); // Message ID
        names.emplace_back("message_id");

        return_types.emplace_back(LogicalType::VARCHAR); // Snippet
        names.emplace_back("snippet");

        return_types.emplace_back(LogicalType::VARCHAR); // Subject
        names.emplace_back("subject");

        return make_uniq<IMAPBindData>(username.ToString(), password.ToString(), server_url.ToString(), limit);
    }

    unique_ptr<GlobalTableFunctionState> IMAPInitGlobal(ClientContext &context, TableFunctionInitInput &input) {
        return make_uniq<IMAPGlobalState>();
    }


    static void IMAPTableFunction(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
        auto &bind_data = (IMAPBindData &)*data.bind_data;
        auto &global_state = data.global_state->Cast<IMAPGlobalState>();

        if (global_state.done) {
            output.SetCardinality(0);
            return;
        }

        if (global_state.emails.empty()) {
            std::cout << "Fetching emails from IMAP server...\n";
            global_state.emails = FetchEmails(bind_data.server_url, bind_data.username, bind_data.password,
                                              bind_data.limit);
            if (global_state.emails.empty()) {
                output.SetCardinality(0);
                global_state.done = true;
                return;
            }
        }

        idx_t remaining_rows = global_state.emails.size() - global_state.current_idx;
        idx_t row_count = MinValue<idx_t>(remaining_rows, STANDARD_VECTOR_SIZE);

        for (idx_t i = 0; i < row_count; i++) {
            const auto &email = global_state.emails[global_state.current_idx + i];
            output.SetValue(0, i, Value(email.at("id")));
            output.SetValue(1, i, Value(email.at("snippet")));
            output.SetValue(2, i, Value(email.at("subject")));
        }

        global_state.current_idx += row_count;
        if (global_state.current_idx >= global_state.emails.size()) {
            global_state.done = true;
        }

        output.SetCardinality(row_count);
    }

    void IMAPFetchFunction::Register(DatabaseInstance &instance) {
        TableFunction fetch_func("imap_fetch", {}, IMAPTableFunction, IMAPBind, IMAPInitGlobal);

        fetch_func.named_parameters["mail_limit"] = LogicalType::BIGINT; // Limit the number of emails
        ExtensionUtil::RegisterFunction(instance, fetch_func);
    }
} // namespace duckdb
