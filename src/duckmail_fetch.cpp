#include "duckmail_fetch.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/common/exception.hpp"
#include <curl/curl.h>
#include <string>
#include <vector>

namespace duckdb {

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

// Function to fetch emails using the Gmail API
static std::vector<std::pair<std::string, std::string>> FetchEmails(const std::string &token) {
    const std::string api_url = "https://www.googleapis.com/gmail/v1/users/me/messages";
    std::string response = SendGetRequest(api_url, token);

    // For simplicity, just extract message IDs and snippets (adjust as needed)
    std::vector<std::pair<std::string, std::string>> emails;

    // Parse response (use yyjson for JSON parsing)
    yyjson_doc *doc = yyjson_read(response.c_str(), response.size(), YYJSON_READ_NOFLAG);
    if (!doc) {
        throw IOException("Failed to parse JSON response.");
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *messages = yyjson_obj_get(root, "messages");
    if (!yyjson_is_arr(messages)) {
        yyjson_doc_free(doc);
        throw IOException("Invalid Gmail API response format: 'messages' not found.");
    }

    size_t idx, max;
    yyjson_val *message;
    yyjson_arr_foreach(messages, idx, max, message) {
        yyjson_val *id = yyjson_obj_get(message, "id");
        yyjson_val *snippet = yyjson_obj_get(message, "snippet");
        if (id && yyjson_is_str(id)) {
            emails.emplace_back(yyjson_get_str(id), snippet ? yyjson_get_str(snippet) : "");
        }
    }

    yyjson_doc_free(doc);
    return emails;
}

// DuckDB table function to fetch emails
static void DuckMailTableFunction(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
    // Retrieve the token from the secret
    auto secret = SecretManager::Get(context).LookupSecret(CatalogTransaction::GetSystemCatalogTransaction(context),
                                                           "/duckmail", "duckmail");
    auto token_value = secret.GetSecret().TryGetValue("token", true);

    if (!token_value || !token_value->IsValid()) {
        throw IOException("Token not found or invalid.");
    }

    std::string token = token_value->ToString();

    // Fetch emails
    auto emails = FetchEmails(token);

    // Populate the output chunk
    idx_t row_count = MinValue<idx_t>(emails.size(), STANDARD_VECTOR_SIZE);
    for (idx_t i = 0; i < row_count; i++) {
        output.SetValue(0, i, Value(emails[i].first));   // Message ID
        output.SetValue(1, i, Value(emails[i].second)); // Snippet
    }
    output.SetCardinality(row_count);
}

// Register the table function
void DuckMailFetchFunction::Register(DatabaseInstance &instance) {
    TableFunction fetch_func("duckmail_fetch", {}, DuckMailTableFunction);
    fetch_func.named_parameters["limit"] = LogicalType::INTEGER;
    fetch_func.return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR};
    fetch_func.names = {"message_id", "snippet"};
    ExtensionUtil::RegisterFunction(instance, fetch_func);
}

} // namespace duckdb