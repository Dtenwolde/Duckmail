//===----------------------------------------------------------------------===//
//                         DuckDB
//
// pragma_create_inbox.hpp
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/main/database.hpp"

namespace duckdb {

	//! Class to register the PRAGMA create_inbox function
	class DuckMailPragmaCreateInbox {
	public:
		//! Register the PRAGMA function
		static void Register(DatabaseInstance &instance);
	};

} // namespace duckdb