#include "duckmail_gmail_send.hpp"
#include "duckdb/function/table_function.hpp"
#include <duckdb/main/extension_util.hpp>

struct DuckMailGlobalState : public GlobalTableFunctionState {
	std::vector<std::map<std::string, std::string>> emails; // Updated type
	idx_t current_idx = 0;
	bool done = false;

	explicit DuckMailGlobalState() = default;
};

namespace duckdb {


void DuckMailGmailSendFunction::Register(DatabaseInstance &instance) {
	TableFunction fetch_func("duckmail_fetch", {}, DuckMailGmailSendTableFunction, DuckMailBind, DuckMailInitGlobal);

	// Add optional named parameters
	fetch_func.named_parameters["mail_limit"] = LogicalType::BIGINT; // Limit the number of emails
	fetch_func.named_parameters["mail_label"] = LogicalType::VARCHAR; // Filter by label (optional)

	// Register the function
	ExtensionUtil::RegisterFunction(instance, fetch_func);
}

} // namespace duckdb