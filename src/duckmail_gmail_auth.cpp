#include "duckmail_auth.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/common/exception.hpp"
#include <fstream>
#include <cstdlib>
#include <iostream>
#include <string>
#include <random>

namespace duckdb {

// Helper function to generate a random string for the OAuth2 `state` parameter
static std::string GenerateRandomString(size_t length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::default_random_engine rng(std::random_device{}());
    std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);
    std::string result;
    for (size_t i = 0; i < length; i++) {
        result += charset[dist(rng)];
    }
    return result;
}

// Implementation of InitiateOAuthFlow
std::string CreateDuckMailSecretFunctions::InitiateOAuthFlow() {
    const std::string client_id = "721513172144-9lq10nn1t56maniaog5kbkm3upinhbu4.apps.googleusercontent.com"; // Replace with your client ID
    const std::string redirect_uri = "https://dtenwolde.github.io/duckmail-auth/";
    const std::string auth_url = "https://accounts.google.com/o/oauth2/v2/auth";
    const std::string scope = "https://www.googleapis.com/auth/gmail.readonly";

    // Generate a random state for CSRF protection
    std::string state = GenerateRandomString(16);

    // Construct the OAuth2 authorization URL
    std::string auth_request_url = auth_url + "?client_id=" + client_id +
                                   "&redirect_uri=" + redirect_uri +
                                   "&response_type=token" +
                                   "&scope=" + scope +
                                   "&state=" + state;

    // Print the URL and prompt the user
    std::cout << "Visit the URL below to authorize DuckMail:\n\n";
    std::cout << auth_request_url << "\n\n";

    // Open the URL in the default browser
#ifdef _WIN32
    system(("start \"\" \"" + auth_request_url + "\"").c_str());
#elif __APPLE__
    system(("open \"" + auth_request_url + "\"").c_str());
#elif __linux__
    system(("xdg-open \"" + auth_request_url + "\"").c_str());
#endif

    // Capture the access token from the user
    std::cout << "After granting permission, paste the access token here: ";
    std::string access_token;
    std::cin >> access_token;

    return access_token;
}

// Function to redact sensitive keys
static void RedactSensitiveKeys(KeyValueSecret &result) {
    result.redact_keys.insert("token");
}

// Create a secret using the OAuth2 token
static unique_ptr<BaseSecret> CreateDuckMailSecretFromOAuth(ClientContext &context, CreateSecretInput &input) {
    auto scope = input.scope;

    auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

    // Initiate OAuth2 flow and obtain token
    std::string token = CreateDuckMailSecretFunctions::InitiateOAuthFlow();

    // Store the token in the secret
    result->secret_map["token"] = Value(token);

    // Redact sensitive keys
    RedactSensitiveKeys(*result);

    return std::move(result);
}

// Register the secret type and provider functions
void CreateDuckMailSecretFunctions::RegisterGmail(DatabaseInstance &instance) {
    const string type = "gmail";

    // Register the new secret type
    SecretType secret_type;
    secret_type.name = type;
    secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
    secret_type.default_provider = "oauth";
    ExtensionUtil::RegisterSecretType(instance, secret_type);

    // Register the OAuth2 secret provider
    CreateSecretFunction oauth_function = {type, "oauth", CreateDuckMailSecretFromOAuth};
    oauth_function.named_parameters["use_oauth"] = LogicalType::BOOLEAN;
    ExtensionUtil::RegisterFunction(instance, oauth_function);
}

} // namespace duckdb