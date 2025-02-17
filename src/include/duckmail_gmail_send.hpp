#pragma once

#include "duckdb.hpp"

namespace duckdb {

	class DuckMailGmailSendFunction {
	public:
		//! Registers the fetch emails table function
		static void Register(DatabaseInstance &instance);
	};

} // namespace duckdb