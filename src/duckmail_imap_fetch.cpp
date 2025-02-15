#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/common/exception.hpp"
#include "duckmail_fetch.hpp"
#include <curl/curl.h>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <future>
#include <iostream>
#include <duckdb/main/extension_util.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <sstream>
#include <unistd.h>
#include <netdb.h>
#include <regex>
#include <cstring> // for std::memset
#include <iomanip>


namespace duckdb {

    static int ResolveAndConnect(const std::string &host, int port) {
        struct addrinfo hints, *res, *p;
        int sockfd = -1;

        // Set hints for getaddrinfo
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
        hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

        std::string port_str = std::to_string(port);

        // Resolve the hostname
        int status = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
        if (status != 0) {
            throw IOException("Failed to resolve host: " + host + ", " + gai_strerror(status));
        }

        // Try each address until we successfully connect
        for (p = res; p != nullptr; p = p->ai_next) {
            // Create the socket
            sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (sockfd < 0) {
                continue; // Try the next address
            }

            // Connect to the server
            if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) {
                break; // Successfully connected
            }

            close(sockfd); // Close the socket on failure
            sockfd = -1;
        }

        freeaddrinfo(res); // Free the address list

        if (sockfd < 0) {
            throw IOException("Failed to connect to host: " + host);
        }

        return sockfd;
    }

    // Helper function to initialize an SSL context
    static SSL_CTX *InitializeSSLContext() {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            throw IOException("Failed to create SSL context.");
        }
        return ctx;
    }

    static SSL *ConnectToIMAPServer(const std::string &host, int port) {
        SSL_CTX *ctx = InitializeSSLContext();
        SSL *ssl = nullptr;
        int sockfd = -1;

        try {
            // Resolve the hostname and connect to the server
            sockfd = ResolveAndConnect(host, port);

            // Create the SSL object
            ssl = SSL_new(ctx);
            if (!ssl) {
                close(sockfd);
                throw IOException("Failed to create SSL object.");
            }

            SSL_set_fd(ssl, sockfd);

            // Establish SSL connection
            if (SSL_connect(ssl) <= 0) {
                close(sockfd);
                SSL_free(ssl);
                throw IOException("Failed to establish SSL connection.");
            }

            std::cout << "Connected to IMAP server " << host << " on port " << port << "\n";
            return ssl;
        } catch (...) {
            if (sockfd >= 0) {
                close(sockfd);
            }
            if (ssl) {
                SSL_free(ssl);
            }
            SSL_CTX_free(ctx);
            throw;
        }
    }

    static int command_counter = 1;

    static std::string SendIMAPCommand(SSL *ssl, const std::string &command) {
        // Generate a unique tag
        std::string tag = "A" + std::to_string(command_counter++);
        std::string formatted_command = tag + " " + command + "\r\n";

        // Send the command
        if (SSL_write(ssl, formatted_command.c_str(), formatted_command.size()) <= 0) {
            throw IOException("Failed to send command: " + command);
        }
        std::cout << "Sent command: " << formatted_command;

        // Read the response
        std::string response;
        char buffer[4096];
        bool found_tagged_response = false;

        while (!found_tagged_response) {
            int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes_read <= 0) {
                throw IOException("Failed to read IMAP response.");
            }
            buffer[bytes_read] = '\0';
            response += buffer;

            // Check if the response contains the expected tag
            if (response.find(tag + " OK") != std::string::npos) {
                found_tagged_response = true;
            }
        }

        std::cout << "Full response for command '" << command << "':\n" << response << "\n";

        // Check if the response contains the expected tag and "OK"
        if (!found_tagged_response) {
            throw IOException("Command '" + command + "' failed or incomplete. Response: " + response);
        }

        return response;
    }

    static void CloseSSLConnection(SSL *ssl, int sockfd) {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (sockfd >= 0) {
            close(sockfd);
        }
    }

    // Parse UIDs from IMAP response
    static std::vector<std::string> ParseUIDSearchResponse(const std::string &response) {
        std::vector<std::string> uids;
        std::istringstream stream(response);
        std::string line;

        while (std::getline(stream, line)) {
            if (line.find("* SEARCH") != std::string::npos) {
                std::istringstream uid_stream(line.substr(line.find("SEARCH") + 7));
                std::string uid;
                while (uid_stream >> uid) {
                    uids.push_back(uid);
                }
            }
        }
        return uids;
    }

    // Fetch valid UIDs from mailbox
    static std::vector<std::string> FetchValidUIDs(SSL *ssl) {
        // SELECT INBOX
        std::cout << "Sending IMAP command: SELECT INBOX\n";
        std::string select_response = SendIMAPCommand(ssl, "SELECT INBOX");
        if (select_response.find("OK") == std::string::npos) {
            throw IOException("SELECT INBOX failed. Response: " + select_response);
        }

        // UID SEARCH ALL
        std::cout << "Sending IMAP command: UID SEARCH ALL\n";
        std::string search_response = SendIMAPCommand(ssl, "UID SEARCH ALL");
        if (search_response.find("OK") == std::string::npos) {
            throw IOException("UID SEARCH ALL failed. Response: " + search_response);
        }

        auto uids = ParseUIDSearchResponse(search_response);
        if (uids.empty()) {
            std::cerr << "No valid UIDs found in mailbox.\n";
        } else {
            std::cout << "Valid UIDs found: ";
            for (const auto &uid: uids) {
                std::cout << uid << " ";
            }
            std::cout << "\n";
        }

        return uids;
    }

  // Helper function to trim whitespace and CRLF
static std::string Trim(const std::string &str) {
    size_t start = str.find_first_not_of(" \r\n");
    size_t end = str.find_last_not_of(" \r\n");
    return (start == std::string::npos || end == std::string::npos) ? "" : str.substr(start, end - start + 1);
}

// Helper function to Base64-decode a string
static std::string Base64Decode(const std::string &input) {
    BIO *bio, *b64;
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    bio = BIO_new_mem_buf(input.data(), input.size());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Do not require newlines

    int decoded_size = BIO_read(bio, buffer, sizeof(buffer) - 1);
    BIO_free_all(bio);

    if (decoded_size < 0) {
        throw std::runtime_error("Base64 decoding failed.");
    }

    return std::string(buffer, decoded_size);
}

// Decode all MIME encoded-word segments in a string
static std::string DecodeMIMEMixedText(const std::string &input) {
    static const std::regex mime_regex(R"(\=\?([^?]+)\?([BQ])\?([^?]+)\?\=)", std::regex::icase);
    std::string result;
    std::sregex_iterator begin(input.begin(), input.end(), mime_regex), end;

    size_t last_pos = 0;
    for (auto it = begin; it != end; ++it) {
        const auto &match = *it;

        // Append plain text preceding the encoded word
        result += input.substr(last_pos, match.position() - last_pos);

        // Decode the MIME encoded-word
        std::string charset = match[1].str();
        std::string encoding = match[2].str();
        std::string encoded_text = match[3].str();

        if (encoding == "B" || encoding == "b") {
            result += Base64Decode(encoded_text);
        } else if (encoding == "Q" || encoding == "q") {
            std::string decoded;
            for (size_t i = 0; i < encoded_text.size(); ++i) {
                if (encoded_text[i] == '_') {
                    decoded += ' '; // '_' maps to space
                } else if (encoded_text[i] == '=' && i + 2 < encoded_text.size()) {
                    char hex[3] = {encoded_text[i + 1], encoded_text[i + 2], 0};
                    decoded += static_cast<char>(std::strtol(hex, nullptr, 16));
                    i += 2;
                } else {
                    decoded += encoded_text[i];
                }
            }
            result += decoded;
        }

        // Update last position
        last_pos = match.position() + match.length();
    }

    // Append remaining plain text after the last encoded word
    result += input.substr(last_pos);

    return result;
}

// Parse a single email address and name
static std::pair<std::string, std::string> ParseEmail(const std::string &line) {
    std::regex email_regex(R"((.*?)\s*<(.+?)>)");
    std::smatch match;

    if (std::regex_match(line, match, email_regex)) {
        std::string name = Trim(match[1].str());
        std::string email = Trim(match[2].str());
        return {DecodeMIMEMixedText(name), email};
    }
    return {"", Trim(line)}; // If no name, treat as plain email
}

// Parse multiple email addresses from a header value
static std::vector<std::pair<std::string, std::string>> ParseEmailList(const std::string &header_value) {
    std::vector<std::pair<std::string, std::string>> result;
    std::istringstream stream(header_value);
    std::string line;
    while (std::getline(stream, line, ',')) {
        result.push_back(ParseEmail(Trim(line)));
    }
    return result;
}

    std::string ConvertDateToStandardFormat(const std::string &input_date) {
        std::istringstream date_stream(input_date);
        std::tm tm = {};
        std::string weekday, timezone_offset;

        // Parse input string
        date_stream >> weekday; // Skip the day name
        if (input_date.find(',') != std::string::npos) {
            date_stream.ignore(1); // Skip the comma
        }
        date_stream >> std::get_time(&tm, "%d %b %Y %H:%M:%S");

        // Convert parsed time to the desired format
        std::ostringstream output;
        output << std::put_time(&tm, "%Y-%m-%d %H:%M:%S"); // Format time without timezone

        return output.str();
    }

// Fetch email details for multiple UIDs
std::vector<std::map<std::string, std::string>> FetchIMAPMessagesDetails(SSL *ssl, const std::vector<std::string> &uids) {
    std::vector<std::map<std::string, std::string>> email_details;

    // Create the UID FETCH command
    std::string uid_list = std::accumulate(
        uids.begin(), uids.end(), std::string(),
        [](const std::string &a, const std::string &b) { return a.empty() ? b : a + "," + b; });
    std::string fetch_command = "UID FETCH " + uid_list + " (BODY[HEADER])";

    // Send command
    std::string response = SendIMAPCommand(ssl, fetch_command);

    // Parse response
    std::istringstream stream(response);
    std::string line;
    std::map<std::string, std::string> details;

    while (std::getline(stream, line)) {
        line = Trim(line);

        // Check for UID and start a new entry
        if (line.find("UID ") != std::string::npos) {
            if (!details.empty()) {
                email_details.push_back(details);
                details.clear();
            }
            size_t uid_start = line.find("UID ") + 4;
            size_t uid_end = line.find(" ", uid_start);
            details["id"] = line.substr(uid_start, uid_end - uid_start);
        }

        // Parse headers
        if (line.find("Subject:") == 0) {
            details["subject"] = DecodeMIMEMixedText(Trim(line.substr(9)));
        } else if (line.find("From:") == 0) {
            auto parsed = ParseEmail(Trim(line.substr(6)));
            details["from_name"] = parsed.first;
            details["from_email"] = parsed.second;
        } else if (line.find("To:") == 0) {
            auto to_list = ParseEmailList(Trim(line.substr(3)));
            std::string to_names, to_emails;
            for (const auto &entry : to_list) {
                if (!to_names.empty()) {
                    to_names += ", ";
                    to_emails += ", ";
                }
                to_names += entry.first;
                to_emails += entry.second;
            }
            details["to_names"] = to_names;
            details["to_emails"] = to_emails;
        } else if (line.find("Cc:") == 0) {
            auto cc_list = ParseEmailList(Trim(line.substr(3)));
            std::string cc_names, cc_emails;
            for (const auto &entry : cc_list) {
                if (!cc_names.empty()) {
                    cc_names += ", ";
                    cc_emails += ", ";
                }
                cc_names += entry.first;
                cc_emails += entry.second;
            }
            details["cc_names"] = cc_names;
            details["cc_emails"] = cc_emails;
        } else if (line.find("Date:") == 0) {
            std::string raw_date = Trim(line.substr(5));
            try {
                details["date"] = ConvertDateToStandardFormat(raw_date);
            } catch (const std::exception &e) {
                details["date"] = "Invalid date"; // Fallback in case of parsing failure
                std::cerr << "Error parsing date: " << raw_date << " - " << e.what() << "\n";
            }
        }
    }

    // Add the last parsed email
    if (!details.empty()) {
        email_details.push_back(details);
    }

    return email_details;
}

    std::vector<std::map<std::string, std::string> > FetchEmails(const std::string &server, int port,
                                                                 const std::string &username,
                                                                 const std::string &password,
                                                                 int64_t limit) {
        // Establish SSL connection to the IMAP server
        int sockfd = -1;
        SSL *ssl = nullptr;

        std::vector<std::map<std::string, std::string> > emails;

        try {
            ssl = ConnectToIMAPServer(server, port);

            // Authenticate user
            std::string login_command = "LOGIN " + username + " " + password;
            std::cout << "Sending IMAP LOGIN command...\n";
            std::string login_response = SendIMAPCommand(ssl, login_command);
            if (login_response.find("OK") == std::string::npos) {
                throw IOException("LOGIN command failed. Response: " + login_response);
            }
            std::cout << "Login successful.\n";

            // Fetch UIDs
            std::cout << "Fetching valid UIDs from mailbox...\n";
            auto uids = FetchValidUIDs(ssl);
            if (uids.empty()) {
                std::cerr << "No valid UIDs found. Mailbox may be empty or commands failed.\n";
                return emails;
            }

            // Apply limit
            if (limit > 0 && uids.size() > static_cast<size_t>(limit)) {
                std::cout << "Applying limit to the number of UIDs. Limit: " << limit << "\n";
                uids.resize(limit);
            }

            // Fetch email details for each UID
            std::cout << "Fetching details for " << uids.size() << " emails...\n";
            emails = FetchIMAPMessagesDetails(ssl, uids);
        //     for (const auto &uid: uids) {
        //         try {
        //             std::cout << "Fetching details for UID: " << uid << "\n";
        //             auto details = FetchIMAPMessagesDetails(ssl, uid);
        //             FetchIMAPMessagesDetails
        //             emails.push_back(details);
        //             std::cout << "Fetched email details for UID: " << uid << "\n";
        //         } catch (const std::exception &e) {
        //             std::cerr << "Error fetching details for UID " << uid << ": " << e.what() << "\n";
        //         }
        //     }
        } catch (const std::exception &e) {
            std::cerr << "Error during email fetching process: " << e.what() << "\n";
        }

        // Close the SSL connection and socket
        CloseSSLConnection(ssl, sockfd);
        return emails;
    }

    struct IMAPGlobalState : public GlobalTableFunctionState {
        std::vector<std::map<std::string, std::string> > emails;
        idx_t current_idx = 0;
        bool done = false;

        explicit IMAPGlobalState() = default;
    };

    struct IMAPBindData : public FunctionData {
        std::string username;
        std::string password;
        std::string server_url;
        int64_t limit;

        explicit IMAPBindData(std::string username_p, std::string password_p, std::string server_url_p, int64_t limit_p)
            : username(std::move(username_p)), password(std::move(password_p)), server_url(std::move(server_url_p)),
              limit(limit_p) {
        }

        unique_ptr<FunctionData> Copy() const override {
            return make_uniq<IMAPBindData>(username, password, server_url, limit);
        }

        bool Equals(const FunctionData &other) const override {
            auto &other_data = (const IMAPBindData &) other;
            return username == other_data.username && password == other_data.password &&
                   server_url == other_data.server_url && limit == other_data.limit;
        }
    };

    unique_ptr<FunctionData> IMAPBind(ClientContext &context, TableFunctionBindInput &input,
                                  vector<LogicalType> &return_types, vector<string> &names) {
    auto &secret_manager = SecretManager::Get(context);
    auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
    auto secret_match = secret_manager.LookupSecret(transaction, "imap", "imap");

    if (!secret_match.HasMatch()) {
        throw InvalidInputException("No 'imap' secret found. Please create a secret with 'CREATE SECRET' first.");
    }

    auto &secret = secret_match.GetSecret();
    if (secret.GetType() != "imap") {
        throw InvalidInputException("Invalid secret type. Expected 'imap', got '%s'", secret.GetType());
    }

    const auto *kv_secret = dynamic_cast<const KeyValueSecret *>(&secret);
    if (!kv_secret) {
        throw InvalidInputException("Invalid secret format for 'imap' secret.");
    }

    Value username, password, server_url;
    if (!kv_secret->TryGetValue("username", username)) {
        throw InvalidInputException("'username' not found in 'imap' secret.");
    }
    if (!kv_secret->TryGetValue("password", password)) {
        throw InvalidInputException("'password' not found in 'imap' secret.");
    }
    if (!kv_secret->TryGetValue("server", server_url)) {
        throw InvalidInputException("'server' not found in 'imap' secret.");
    }

    // Parse optional limit parameter
    int64_t limit = -1;
    if (input.named_parameters.find("mail_limit") != input.named_parameters.end()) {
        limit = input.named_parameters.at("mail_limit").GetValue<int64_t>();
    }

    // Set output schema
    return_types.emplace_back(LogicalType::VARCHAR); // Message ID
    names.emplace_back("message_id");

    return_types.emplace_back(LogicalType::VARCHAR); // From email
    names.emplace_back("from_email");

    return_types.emplace_back(LogicalType::VARCHAR); // From name
    names.emplace_back("from_name");

    return_types.emplace_back(LogicalType::VARCHAR); // To emails (comma-separated)
    names.emplace_back("to_emails");

    return_types.emplace_back(LogicalType::VARCHAR); // To names (comma-separated)
    names.emplace_back("to_names");

    return_types.emplace_back(LogicalType::VARCHAR); // CC emails (comma-separated)
    names.emplace_back("cc_emails");

    return_types.emplace_back(LogicalType::VARCHAR); // CC names (comma-separated)
    names.emplace_back("cc_names");

    return_types.emplace_back(LogicalType::VARCHAR); // Subject
    names.emplace_back("subject");

    return_types.emplace_back(LogicalType::VARCHAR); // Date
    names.emplace_back("date");

    return make_uniq<IMAPBindData>(username.ToString(), password.ToString(), server_url.ToString(), limit);
}

unique_ptr<GlobalTableFunctionState> IMAPInitGlobal(ClientContext &context, TableFunctionInitInput &input) {
    return make_uniq<IMAPGlobalState>();
}

static void IMAPTableFunction(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
    auto &bind_data = (IMAPBindData &) *data.bind_data;
    auto &global_state = data.global_state->Cast<IMAPGlobalState>();

    if (global_state.done) {
        output.SetCardinality(0);
        return;
    }

    if (global_state.emails.empty()) {
        std::cout << "Fetching emails from IMAP server...\n";
        global_state.emails = FetchEmails(bind_data.server_url, 993, bind_data.username, bind_data.password,
                                          bind_data.limit);
        if (global_state.emails.empty()) {
            output.SetCardinality(0);
            global_state.done = true;
            return;
        }
    }

    idx_t remaining_rows = global_state.emails.size() - global_state.current_idx;
    idx_t row_count = MinValue<idx_t>(remaining_rows, STANDARD_VECTOR_SIZE);

        for (idx_t i = 0; i < row_count; i++) {
            const auto &email = global_state.emails[global_state.current_idx + i];

            auto get_or_default = [](const std::map<std::string, std::string> &map, const std::string &key, const std::string &default_value = "") {
                auto it = map.find(key);
                return (it != map.end() && !it->second.empty()) ? it->second : default_value;
            };

            output.SetValue(0, i, Value(get_or_default(email, "id", "unknown_id")));
            output.SetValue(1, i, Value(get_or_default(email, "from_email", "unknown_email")));
            output.SetValue(2, i, Value(get_or_default(email, "from_name", "unknown_name")));
            output.SetValue(3, i, Value(get_or_default(email, "to_emails", ""))); // Empty string if no recipients
            output.SetValue(4, i, Value(get_or_default(email, "to_names", ""))); // Empty string if no recipient names
            output.SetValue(5, i, Value(get_or_default(email, "cc_emails", ""))); // Empty string if no CC
            output.SetValue(6, i, Value(get_or_default(email, "cc_names", ""))); // Empty string if no CC names
            output.SetValue(7, i, Value(get_or_default(email, "subject", "No Subject")));
            output.SetValue(8, i, Value(get_or_default(email, "date", "Unknown Date")));
        }

    global_state.current_idx += row_count;
    if (global_state.current_idx >= global_state.emails.size()) {
        global_state.done = true;
    }

    output.SetCardinality(row_count);
}

    void IMAPFetchFunction::Register(DatabaseInstance &instance) {
        TableFunction fetch_func("imap_fetch", {}, IMAPTableFunction, IMAPBind, IMAPInitGlobal);

        fetch_func.named_parameters["mail_limit"] = LogicalType::BIGINT; // Limit the number of emails
        ExtensionUtil::RegisterFunction(instance, fetch_func);
    }
} // namespace duckdb
