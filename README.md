# JWTexposer - Web Version

JWTexposer is an automated tool designed to extract and analyze JWTs (JSON Web Tokens) from URLs. This web version is an enhancement of the original command-line tool [JWTXposer](https://github.com/chaudharyarjun/JWTXposer), which provides the same functionality but in a web interface. The tool scans URLs from the Wayback Machine for JWTs and decodes them to reveal potentially sensitive fields like email, password, API keys, and more.

### Features

- **Web Interface**: Easy-to-use web interface to input domain names and analyze JWTs found in archived URLs.
- **JWT Extraction**: Automatically extracts JWTs from URLs found in the Wayback Machine.
- **JWT Decoding**: Decodes JWTs and displays useful fields like email, username, password, and more.
- **Concurrency**: Uses threading to speed up the process of checking URLs and extracting JWTs.
- **Basic Authentication**: Simple authentication mechanism to protect the tool from unauthorized access.
