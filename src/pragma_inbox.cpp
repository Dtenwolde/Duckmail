#include "duckdb/main/extension_util.hpp"
#include "duckdb/function/pragma_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "pragma_inbox.hpp"

namespace duckdb {

	static string PragmaCreateInboxQuery(ClientContext &context, const FunctionParameters &parameters) {
		// Check if the correct number of parameters is provided
		if (parameters.values.size() != 1) {
			throw InvalidInputException("PRAGMA create_inbox requires exactly one parameter: mail_limit");
		}

		// Extract the mail_limit parameter
		int64_t mail_limit = parameters.values[0].GetValue<int64_t>();

		// Generate the query to create or replace the `duckmail_inbox` table
		return "CREATE OR REPLACE TABLE duckmail_inbox AS SELECT * FROM duckmail_fetch(mail_limit = " +
					 std::to_string(mail_limit) + ", mail_label = 'INBOX')";
	}

void DuckMailPragmaCreateInbox::Register(DatabaseInstance &instance) {
    // Define the pragma function
    auto pragma_func = PragmaFunction::PragmaCall(
        "create_inbox",                 // Name of the pragma
        PragmaCreateInboxQuery,         // Query substitution function
        {LogicalType::BIGINT}           // Parameter types (mail_limit is an integer)
    );

    // Register the pragma function
    ExtensionUtil::RegisterFunction(instance, pragma_func);
}
}