# Apple Ads Golang Demo

This Go-based project demonstrates how to authenticate with the Apple Search Ads Campaign Management API using OAuth 2.0. It specifically covers the steps to create a client secret and request an access token, allowing for authenticated API requests without sharing user credentials.

## Overview

The Apple Search Ads Campaign Management API's transition to OAuth 2.0 offers a more secure authentication method. This project simplifies the OAuth 2.0 implementation process, focusing on generating client secrets and accessing tokens.

## Prerequisites

Before you begin, ensure you have the following:

- Go (1.15 or newer)
- Git
- A public-private keypair
- Client Credentials from your Apple Search Ads account

## Configuration

Replace the following placeholders in the code with your actual data from the Apple Search Ads account:

- `clientID`: Your client ID.
- `teamID`: Your team ID.
- `keyID`: Your key ID.
- `keyFilePath`: Path to your private key file.

## Getting Started

Follow these steps to get the project up and running on your local machine:

### 1. Clone the Repository

```bash
git clone https://github.com/liangjianghu/apple-ads-golang-demo.git
cd apple-ads-golang-demo
```

### 2. Initialize Go Module

```bash
go mod init oauth
```

### 3. Install Dependencies

```bash
go get github.com/golang-jwt/jwt/v5
```

### 4. Run the Application

```bash
go run .
```

## Implementation Steps

This project follows these steps, as outlined in the [Apple Search Ads API documentation](https://developer.apple.com/documentation/apple_search_ads/implementing_oauth_for_the_apple_search_ads_api):

### 1. Create a client secret: Generates a JWT token signed with your private key.
### 2. Request an access token: Uses the generated client secret to request an access token.

## Contributing

We welcome contributions! Please fork the repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License.

## Acknowledgments

- Apple Inc. for the Apple Search Ads API documentation.
- The Go and JWT communities for their support and resources.


