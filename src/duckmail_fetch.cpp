#include "duckmail_fetch.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/common/exception.hpp"
#include <curl/curl.h>
#include <string>
#include <vector>
#include <duckdb/main/extension_util.hpp>
#include <json.hpp>
#include <iostream>

namespace duckdb {

using json = nlohmann::json;

std::vector<std::string> ParseGmailResponse(const std::string &response) {
    std::vector<std::string> message_ids;
    try {
        auto parsed_json = json::parse(response);
        if (parsed_json.contains("messages") && parsed_json["messages"].is_array()) {
            for (const auto &message : parsed_json["messages"]) {
                std::string id = message.value("id", "");
                if (!id.empty()) {
                    message_ids.push_back(id);
                }
            }
        } else {
            throw std::runtime_error("Invalid Gmail API response: 'messages' field missing or not an array.");
        }
    } catch (const json::exception &e) {
        std::cerr << "JSON parsing error: " << e.what() << std::endl;
        throw std::runtime_error("Failed to parse Gmail API response.");
    }
    return message_ids;
}

// Helper function to send an HTTP GET request using cURL
static std::string SendGetRequest(const std::string &url, const std::string &token) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        throw IOException("Failed to initialize cURL.");
    }

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_slist_append(nullptr, ("Authorization: Bearer " + token).c_str()));
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
    return response;
}

std::pair<std::string, std::map<std::string, std::string>> FetchMessageDetails(const std::string &message_id, const std::string &token) {
    std::string api_url = "https://www.googleapis.com/gmail/v1/users/me/messages/" + message_id + "?format=full";
    std::string response = SendGetRequest(api_url, token);

    try {
        auto parsed_json = json::parse(response);
        std::map<std::string, std::string> details;
        details["id"] = message_id;

        if (parsed_json.contains("payload") && parsed_json["payload"].contains("headers")) {
            for (const auto &header : parsed_json["payload"]["headers"]) {
                std::string name = header.value("name", "");
                std::string value = header.value("value", "");
                if (name == "From" || name == "To") {
                    // Split into name and email
                    size_t start = value.find('<');
                    size_t end = value.find('>');
                    if (start != std::string::npos && end != std::string::npos && end > start) {
                        details[name + "_email"] = value.substr(start + 1, end - start - 1);
                        details[name + "_name"] = value.substr(0, start - 1); // Exclude trailing space
                    } else {
                        details[name + "_email"] = value;
                        details[name + "_name"] = ""; // No name available
                    }
                } else if (!name.empty()) {
                    details[name] = value;
                }
            }
        }

        if (parsed_json.contains("snippet")) {
            details["snippet"] = parsed_json.value("snippet", "");
        }

        if (parsed_json.contains("labelIds") && parsed_json["labelIds"].is_array()) {
            std::string labels = "";
            for (const auto &label : parsed_json["labelIds"]) {
                labels += label.get<std::string>() + ",";
            }
            if (!labels.empty()) {
                labels.pop_back(); // Remove trailing comma
                details["labels"] = labels;
            }
        }

        if (parsed_json.contains("payload") && parsed_json["payload"].contains("parts")) {
            for (const auto &part : parsed_json["payload"]["parts"]) {
                if (part.contains("filename") && !part["filename"].get<std::string>().empty()) {
                    details["attachments"] += part["filename"].get<std::string>() + ",";
                }
            }
            if (!details["attachments"].empty()) {
                details["attachments"].pop_back(); // Remove trailing comma
            }
        }

        return {message_id, details};
    } catch (const json::exception &e) {
        std::cerr << "JSON parsing error: " << e.what() << std::endl;
        throw std::runtime_error("Failed to parse Gmail message details.");
    }
}

    std::vector<std::map<std::string, std::string>> FetchEmails(const std::string &token, int64_t limit, const std::string &label) {
    std::string api_url = "https://www.googleapis.com/gmail/v1/users/me/messages";
    std::string query_params = "?";
    if (!label.empty()) {
        query_params += "q=label:" + label + "&";
    }
    if (limit > 0) {
        query_params += "maxResults=" + std::to_string(limit);
    }

    std::string response = SendGetRequest(api_url + query_params, token);
    std::vector<std::string> message_ids = ParseGmailResponse(response);

    std::vector<std::map<std::string, std::string>> email_details;
    for (const auto &id : message_ids) {
        auto details = FetchMessageDetails(id, token).second; // Fetch detailed information
        email_details.push_back(details);
        if (email_details.size() >= static_cast<size_t>(limit)) {
            break;
        }
    }
    return email_details;
}

struct DuckMailGlobalState : public GlobalTableFunctionState {
    std::vector<std::map<std::string, std::string>> emails; // Updated type
    idx_t current_idx = 0;
    bool done = false;

    explicit DuckMailGlobalState() = default;
};

struct DuckMailBindData : public FunctionData {
    std::string token;
    int64_t limit;
    std::string label;

    explicit DuckMailBindData(std::string token_p, int64_t limit_p, std::string label_p)
        : token(std::move(token_p)), limit(limit_p), label(std::move(label_p)) {}

    unique_ptr<FunctionData> Copy() const override {
        return make_uniq<DuckMailBindData>(token, limit, label);
    }

    bool Equals(const FunctionData &other) const override {
        auto &other_data = (const DuckMailBindData &)other;
        return token == other_data.token && limit == other_data.limit && label == other_data.label;
    }
};

unique_ptr<FunctionData> DuckMailBind(ClientContext &context, TableFunctionBindInput &input,
                                      vector<LogicalType> &return_types, vector<string> &names) {
    auto &secret_manager = SecretManager::Get(context);
    auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
    auto secret_match = secret_manager.LookupSecret(transaction, "duckmail", "duckmail");

    if (!secret_match.HasMatch()) {
        throw InvalidInputException("No 'duckmail' secret found. Please create a secret with 'CREATE SECRET' first.");
    }

    auto &secret = secret_match.GetSecret();
    if (secret.GetType() != "duckmail") {
        throw InvalidInputException("Invalid secret type. Expected 'duckmail', got '%s'", secret.GetType());
    }

    const auto *kv_secret = dynamic_cast<const KeyValueSecret *>(&secret);
    if (!kv_secret) {
        throw InvalidInputException("Invalid secret format for 'duckmail' secret.");
    }

    Value token_value;
    if (!kv_secret->TryGetValue("token", token_value)) {
        throw InvalidInputException("'token' not found in 'duckmail' secret.");
    }

    std::string token = token_value.ToString();

    // Parse optional limit parameter
    int64_t limit = -1;
    if (input.named_parameters.find("mail_limit") != input.named_parameters.end()) {
        limit = input.named_parameters.at("mail_limit").GetValue<int64_t>();
    }

    // Parse optional label parameter
    std::string label = ""; // Default to fetching all emails if no label is provided
    if (input.named_parameters.find("mail_label") != input.named_parameters.end()) {
        label = input.named_parameters.at("mail_label").GetValue<std::string>();
    }

    // Set output schema
    return_types.emplace_back(LogicalType::VARCHAR); // Message ID
    names.emplace_back("message_id");

    return_types.emplace_back(LogicalType::VARCHAR); // Sender Name
    names.emplace_back("sender_name");

    return_types.emplace_back(LogicalType::VARCHAR); // Sender Email
    names.emplace_back("sender_email");

    return_types.emplace_back(LogicalType::VARCHAR); // Recipient Name
    names.emplace_back("recipient_name");

    return_types.emplace_back(LogicalType::VARCHAR); // Recipient Email
    names.emplace_back("recipient_email");

    return_types.emplace_back(LogicalType::VARCHAR); // Snippet
    names.emplace_back("snippet");

    return_types.emplace_back(LogicalType::VARCHAR); // Subject
    names.emplace_back("subject");

    return_types.emplace_back(LogicalType::VARCHAR); // Labels
    names.emplace_back("labels");

    return_types.emplace_back(LogicalType::VARCHAR); // Attachments
    names.emplace_back("attachments");

    return make_uniq<DuckMailBindData>(token, limit, label);
}

unique_ptr<GlobalTableFunctionState> DuckMailInitGlobal(ClientContext &context, TableFunctionInitInput &input) {
    return make_uniq<DuckMailGlobalState>();
}

static void DuckMailTableFunction(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
    auto &bind_data = (DuckMailBindData &)*data.bind_data;
    auto &global_state = data.global_state->Cast<DuckMailGlobalState>();

    // Exit early if done
    if (global_state.done) {
        output.SetCardinality(0);
        return;
    }

    // Fetch emails if not already fetched
    if (global_state.emails.empty()) {
        global_state.emails = FetchEmails(bind_data.token, bind_data.limit, bind_data.label); // Pass label filter
    }

    // Calculate remaining rows to fetch
    idx_t remaining_rows = global_state.emails.size() - global_state.current_idx;
    idx_t row_count = MinValue<idx_t>(remaining_rows, STANDARD_VECTOR_SIZE);

    // Populate output chunk
    for (idx_t i = 0; i < row_count; i++) {
        const auto &email = global_state.emails[global_state.current_idx + i];

        // Utility function to safely extract values from the map
        auto GetValueOrDefault = [](const std::map<std::string, std::string> &map, const std::string &key) -> std::string {
            auto it = map.find(key);
            return it != map.end() ? it->second : "";
        };

        output.SetValue(0, i, Value(GetValueOrDefault(email, "id")));             // Message ID
        output.SetValue(1, i, Value(GetValueOrDefault(email, "From_name")));     // Sender Name
        output.SetValue(2, i, Value(GetValueOrDefault(email, "From_email")));    // Sender Email
        output.SetValue(3, i, Value(GetValueOrDefault(email, "To_name")));       // Recipient Name
        output.SetValue(4, i, Value(GetValueOrDefault(email, "To_email")));      // Recipient Email
        output.SetValue(5, i, Value(GetValueOrDefault(email, "snippet")));       // Snippet
        output.SetValue(6, i, Value(GetValueOrDefault(email, "Subject")));       // Subject
        output.SetValue(7, i, Value(GetValueOrDefault(email, "labels")));        // Labels
        output.SetValue(8, i, Value(GetValueOrDefault(email, "attachments")));   // Attachments
    }

    // Update state and check if done
    global_state.current_idx += row_count;
    if (global_state.current_idx >= global_state.emails.size() || global_state.current_idx >= static_cast<idx_t>(bind_data.limit)) {
        global_state.done = true;
    }

    output.SetCardinality(row_count);
}

void DuckMailFetchFunction::Register(DatabaseInstance &instance) {
    TableFunction fetch_func("duckmail_fetch", {}, DuckMailTableFunction, DuckMailBind, DuckMailInitGlobal);

    // Add optional named parameters
    fetch_func.named_parameters["mail_limit"] = LogicalType::BIGINT; // Limit the number of emails
    fetch_func.named_parameters["mail_label"] = LogicalType::VARCHAR; // Filter by label (optional)

    // Register the function
    ExtensionUtil::RegisterFunction(instance, fetch_func);
}

} // namespace duckdb