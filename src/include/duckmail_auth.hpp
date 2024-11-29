#pragma once

#include <string>
#include "duckdb/main/database.hpp"

namespace duckdb {

	class CreateDuckMailSecretFunctions {
	public:
		//! Initiates the OAuth flow and retrieves an access token
		static std::string InitiateOAuthFlow();

		//! Register all CreateSecretFunctions
		static void RegisterGmail(DatabaseInstance &instance);
		static void RegisterImap(DatabaseInstance &instance);
	};

} // namespace duckdb