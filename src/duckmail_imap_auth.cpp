#include "duckmail_auth.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/common/exception.hpp"
#include <string>
#include <iostream>
#include <map>

namespace duckdb {

// Helper function to redact sensitive keys
static void RedactSensitiveKeys(KeyValueSecret &result) {
    result.redact_keys.insert("username");
    result.redact_keys.insert("password");
}

// Create a secret for IMAP configuration
static unique_ptr<BaseSecret> CreateImapSecret(ClientContext &context, CreateSecretInput &input) {
    // Parse mandatory named parameters
    auto username_it = input.options.find("username");
    auto password_it = input.options.find("password");

    if (username_it == input.options.end() || password_it == input.options.end()) {
        throw InvalidInputException(
            "CREATE SECRET for IMAP requires the 'username' and 'password' options.");
    }

    std::string username = username_it->second.ToString();
    std::string password = password_it->second.ToString();

    // Parse optional named parameters
    std::string server = "imap.example.com"; // Default IMAP server
    int port = 993;                         // Default IMAP port

    auto server_it = input.options.find("server");
    if (server_it != input.options.end()) {
        server = server_it->second.ToString();
    }

    auto port_it = input.options.find("port");
    if (port_it != input.options.end()) {
        port = port_it->second.GetValue<int32_t>();
    }

    // Store these details in a KeyValueSecret
    auto result = make_uniq<KeyValueSecret>(input.scope, input.type, input.provider, input.name);
    result->secret_map["username"] = Value(username);
    result->secret_map["password"] = Value(password);
    result->secret_map["server"] = Value(server);
    result->secret_map["port"] = Value(port);

    // Redact sensitive keys for security
    RedactSensitiveKeys(*result);

    return std::move(result);
}

// Register the IMAP secret type and provider
void CreateDuckMailSecretFunctions::RegisterImap(DatabaseInstance &instance) {
    const std::string type = "imap";

    // Define the secret type
    SecretType secret_type;
    secret_type.name = type;
    secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
    secret_type.default_provider = "manual";

    // Register the secret type
    ExtensionUtil::RegisterSecretType(instance, secret_type);

    // Register the IMAP secret provider
    CreateSecretFunction imap_function = {type, "manual", CreateImapSecret};
    imap_function.named_parameters["username"] = LogicalType::VARCHAR; // Required
    imap_function.named_parameters["password"] = LogicalType::VARCHAR; // Required
    imap_function.named_parameters["server"] = LogicalType::VARCHAR;   // Optional
    imap_function.named_parameters["port"] = LogicalType::INTEGER;     // Optional

    ExtensionUtil::RegisterFunction(instance, imap_function);
}

} // namespace duckdb