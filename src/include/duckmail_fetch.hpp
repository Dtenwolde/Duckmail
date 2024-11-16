#pragma once

#include "duckdb.hpp"

namespace duckdb {

	class DuckMailFetchFunction {
	public:
		//! Registers the fetch emails table function
		static void Register(DatabaseInstance &instance);
	};

} // namespace duckdb