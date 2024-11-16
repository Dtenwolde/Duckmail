#define DUCKDB_EXTENSION_MAIN

#include "duckmail_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include "duckdb/main/secret/secret_manager.hpp"

// OpenSSL linked through vcpkg
#include <duckmail_auth.hpp>
#include <openssl/opensslv.h>
#include <curl/curl.h>
#include <yyjson.hpp>

namespace duckdb {

inline void DuckmailScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &name_vector = args.data[0];
    UnaryExecutor::Execute<string_t, string_t>(
	    name_vector, result, args.size(),
	    [&](string_t name) {
			return StringVector::AddString(result, "Duckmail "+name.GetString()+" 🐥");;
        });
}

inline void DuckmailOpenSSLVersionScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &name_vector = args.data[0];
    UnaryExecutor::Execute<string_t, string_t>(
	    name_vector, result, args.size(),
	    [&](string_t name) {
			return StringVector::AddString(result, "Duckmail " + name.GetString() +
                                                     ", my linked OpenSSL version is " +
                                                     OPENSSL_VERSION_TEXT );;
        });
}

// // Define the secret creation function
// static unique_ptr<BaseSecret> CreateIMAPSecret(ClientContext &context, CreateSecretInput &input) {
//     // Check required parameters
//     if (!input.options.count("username") || !input.options.count("password") || !input.options.count("server")) {
//         throw InvalidInputException("IMAP Secret requires 'username', 'password', and 'server' parameters.");
//     }
//
//     auto secret = make_uniq<KeyValueSecret>(
//         input.scope, input.type, input.provider, input.name.empty() ? "imap_secret" : input.name);
//
//     // Set the values in the secret map
//     secret->TrySetValue("username", input);
//     secret->TrySetValue("password", input);
//     secret->TrySetValue("server", input);
//
//     // Redact sensitive keys
//     secret->redact_keys.insert("password");
//
//     return secret;
// }

// // Register the IMAP secret type
// static void RegisterIMAPSecret(DatabaseInstance &instance) {
//     auto &secret_manager = SecretManager::Get(instance);
//
//     // Register the secret type
//     SecretType imap_secret_type;
//     imap_secret_type.name = "imap";
//     imap_secret_type.deserializer = IMAPSecretDeserializer;
//     imap_secret_type.default_provider = "user_provided";
//
//     secret_manager.RegisterSecretType(imap_secret_type);
//
//     // Add a CreateSecretFunction for the IMAP type
//     CreateSecretFunction imap_create_function;
//     imap_create_function.secret_type = "imap";
//     imap_create_function.provider = "user_provided";
//     imap_create_function.function = CreateIMAPSecret;
//
//     // Define the expected parameters
//     imap_create_function.named_parameters["username"] = LogicalType::VARCHAR;
//     imap_create_function.named_parameters["password"] = LogicalType::VARCHAR;
//     imap_create_function.named_parameters["server"] = LogicalType::VARCHAR;
//
//     secret_manager.RegisterSecretFunction(imap_create_function, OnCreateConflict::ERROR_ON_CONFLICT);
// }

static void LoadInternal(DatabaseInstance &instance) {
    // Register a scalar function
    auto duckmail_scalar_function = ScalarFunction("duckmail", {LogicalType::VARCHAR}, LogicalType::VARCHAR, DuckmailScalarFun);
    ExtensionUtil::RegisterFunction(instance, duckmail_scalar_function);

    // Register another scalar function
    auto duckmail_openssl_version_scalar_function = ScalarFunction("duckmail_openssl_version", {LogicalType::VARCHAR},
                                                LogicalType::VARCHAR, DuckmailOpenSSLVersionScalarFun);
    ExtensionUtil::RegisterFunction(instance, duckmail_openssl_version_scalar_function);
		CreateDuckMailSecretFunctions::Register(instance);
}

void DuckmailExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}
std::string DuckmailExtension::Name() {
	return "duckmail";
}

std::string DuckmailExtension::Version() const {
#ifdef EXT_VERSION_DUCKMAIL
	return EXT_VERSION_DUCKMAIL;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void duckmail_init(duckdb::DatabaseInstance &db) {
    duckdb::DuckDB db_wrapper(db);
    db_wrapper.LoadExtension<duckdb::DuckmailExtension>();
}

DUCKDB_EXTENSION_API const char *duckmail_version() {
	return duckdb::DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
