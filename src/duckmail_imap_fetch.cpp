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


namespace duckdb {

#include <netdb.h>
#include <cstring> // for std::memset

    static int ResolveAndConnect(const std::string &host, int port) {
        struct addrinfo hints, *res, *p;
        int sockfd = -1;

        // Set hints for getaddrinfo
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;    // Allow IPv4 or IPv6
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
    std::vector<std::string> uids;

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

    uids = ParseUIDSearchResponse(search_response);
    if (uids.empty()) {
        std::cerr << "No valid UIDs found in mailbox.\n";
    } else {
        std::cout << "Valid UIDs found: ";
        for (const auto &uid : uids) {
            std::cout << uid << " ";
        }
        std::cout << "\n";
    }

    return uids;
}

// Helper function to trim trailing whitespace or \r
static std::string Trim(const std::string &str) {
    size_t end = str.find_last_not_of("\r\n \t");
    return (end == std::string::npos) ? "" : str.substr(0, end + 1);
}

// Helper function to Base64-decode a string
static std::string Base64Decode(const std::string &input) {
    BIO *bio, *b64;
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    // Setup Base64 decoding
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
            // Decode quoted-printable
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

// Updated function to parse "From" field
static std::pair<std::string, std::string> ParseFromField(const std::string &from) {
    std::string name, email;

    size_t start_angle = from.find('<');
    size_t end_angle = from.find('>');

    if (start_angle != std::string::npos && end_angle != std::string::npos && start_angle < end_angle) {
        email = from.substr(start_angle + 1, end_angle - start_angle - 1);
        name = from.substr(0, start_angle);
    } else {
        // If no angle brackets, treat the entire field as the email
        email = from;
    }

    // Trim and decode both name and email
    name = Trim(name);
    email = Trim(email);

    // Decode MIME encoded names
    name = DecodeMIMEMixedText(name);

    return {name, email};
}
// Fetch email details for a given UID
static std::map<std::string, std::string> FetchIMAPMessageDetails(SSL *ssl, const std::string &uid) {
    std::string fetch_command = "UID FETCH " + uid + " (BODY[HEADER])";
    std::string response = SendIMAPCommand(ssl, fetch_command);

    std::map<std::string, std::string> details;
    details["id"] = uid;

    std::istringstream stream(response);
    std::string line;
    std::string from_field;

    while (std::getline(stream, line)) {
        if (line.find("Subject:") == 0) {
            details["subject"] = Trim(line.substr(9)); // Trim the subject
        } else if (line.find("From:") == 0) {
            from_field = Trim(line.substr(6)); // Capture the raw "From" field
        }
    }

    if (details.find("subject") == details.end()) {
        details["subject"] = "No subject found.";
    }

    if (!from_field.empty()) {
        auto [name, email] = ParseFromField(from_field);
        details["from_name"] = name.empty() ? "Unknown sender" : name;
        details["from_email"] = email;
    } else {
        details["from_name"] = "Unknown sender";
        details["from_email"] = "No email address found.";
    }

    return details;
}

std::vector<std::map<std::string, std::string>> FetchEmails(const std::string &server, int port,
                                                            const std::string &username, const std::string &password,
                                                            int64_t limit) {
    // Establish SSL connection to the IMAP server
    int sockfd = -1;
    SSL *ssl = nullptr;

    std::vector<std::map<std::string, std::string>> emails;

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
        for (const auto &uid : uids) {
            try {
                std::cout << "Fetching details for UID: " << uid << "\n";
                auto details = FetchIMAPMessageDetails(ssl, uid);
                emails.push_back(details);
                std::cout << "Fetched email details for UID: " << uid << "\n";
            } catch (const std::exception &e) {
                std::cerr << "Error fetching details for UID " << uid << ": " << e.what() << "\n";
            }
        }

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

        return_types.emplace_back(LogicalType::VARCHAR); // from_email
        names.emplace_back("from_email");

        return_types.emplace_back(LogicalType::VARCHAR); // from_name
        names.emplace_back("from_name");

        return_types.emplace_back(LogicalType::VARCHAR); // Subject
        names.emplace_back("subject");

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
            output.SetValue(0, i, Value(email.at("id")));
            output.SetValue(1, i, Value(email.at("from_email")));
            output.SetValue(2, i, Value(email.at("from_name")));
            output.SetValue(3, i, Value(email.at("subject")));
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
