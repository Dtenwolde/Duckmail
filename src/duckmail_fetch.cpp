#include "duckmail_fetch.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/common/exception.hpp"
#include <curl/curl.h>
#include <string>
#include <vector>
#include <duckdb/main/extension_util.hpp>
#include <json.hpp>
#include <iostream> // For debugging

namespace duckdb {

using json = nlohmann::json;

// Function to parse the Gmail API response
std::vector<std::pair<std::string, std::string>> ParseGmailResponse(const std::string &response) {
    std::vector<std::pair<std::string, std::string>> emails;

    try {
        std::cout << "Parsing Gmail API response..." << std::endl; // Debugging

        auto parsed_json = json::parse(response);
        if (parsed_json.contains("messages") && parsed_json["messages"].is_array()) {
            for (const auto &message : parsed_json["messages"]) {
                std::string id = message.value("id", "");
                std::string snippet = message.value("snippet", "");
                emails.emplace_back(id, snippet);
            }
        } else {
            throw std::runtime_error("Invalid Gmail API response: 'messages' field missing or not an array.");
        }
    } catch (const json::exception &e) {
        std::cerr << "JSON parsing error: " << e.what() << std::endl;
        throw std::runtime_error("Failed to parse Gmail API response.");
    }

    std::cout << "Parsed " << emails.size() << " emails from the response." << std::endl; // Debugging
    return emails;
}

// Helper function to send an HTTP GET request using cURL
static std::string SendGetRequest(const std::string &url, const std::string &token) {
    std::cout << "Sending GET request to URL: " << url << std::endl; // Debugging

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
        std::cerr << "cURL error: " << curl_easy_strerror(res) << std::endl; // Debugging
        curl_easy_cleanup(curl);
        throw IOException("cURL error: " + std::string(curl_easy_strerror(res)));
    }

    curl_easy_cleanup(curl);
    std::cout << "Received response from Gmail API." << std::endl; // Debugging
    return response;
}

static std::vector<std::pair<std::string, std::string>> FetchEmails(const std::string &token) {
    const std::string api_url = "https://www.googleapis.com/gmail/v1/users/me/messages";
    std::cout << "Fetching emails using the Gmail API..." << std::endl; // Debugging

    std::string response = SendGetRequest(api_url, token);
    return ParseGmailResponse(response);
}

struct DuckMailBindData : public FunctionData {
    std::string token;

    explicit DuckMailBindData(std::string token_p) : token(std::move(token_p)) {}
    unique_ptr<FunctionData> Copy() const override { return make_uniq<DuckMailBindData>(token); }
    bool Equals(const FunctionData &other) const override {
        auto &other_data = (const DuckMailBindData &)other;
        return token == other_data.token;
    }
};

unique_ptr<FunctionData> DuckMailBind(ClientContext &context, TableFunctionBindInput &input,
                                      vector<LogicalType> &return_types, vector<string> &names) {
    std::cout << "Binding function 'duckmail_fetch'..." << std::endl; // Debugging

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
    std::cout << "Retrieved token for Gmail API." << std::endl; // Debugging

    // Set output schema
    return_types.emplace_back(LogicalType::VARCHAR); // Message ID
    names.emplace_back("message_id");

    return_types.emplace_back(LogicalType::VARCHAR); // Snippet
    names.emplace_back("snippet");

    return make_uniq<DuckMailBindData>(token);
}

static void DuckMailTableFunction(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
    std::cout << "Executing 'duckmail_fetch' table function..." << std::endl; // Debugging

    auto &bind_data = (DuckMailBindData &)*data.bind_data;
    auto emails = FetchEmails(bind_data.token);

    idx_t row_count = MinValue<idx_t>(emails.size(), STANDARD_VECTOR_SIZE);
    for (idx_t i = 0; i < row_count; i++) {
        output.SetValue(0, i, Value(emails[i].first));   // Message ID
        output.SetValue(1, i, Value(emails[i].second)); // Snippet
    }
    output.SetCardinality(row_count);

    std::cout << "Returned " << row_count << " rows from Gmail API." << std::endl; // Debugging
}

void DuckMailFetchFunction::Register(DatabaseInstance &instance) {
    std::cout << "Registering 'duckmail_fetch' function..." << std::endl; // Debugging
    TableFunction fetch_func("duckmail_fetch", {}, DuckMailTableFunction, DuckMailBind);
    ExtensionUtil::RegisterFunction(instance, fetch_func);
}

} // namespace duckdb