# Zoho Creator MCP Server

This repository contains a Model Context Protocol (MCP) server implementation for Zoho Creator, allowing you to interact with Zoho Creator applications programmatically through the Model Context Protocol (MCP).

## Overview

The Zoho Creator MCP server acts as a bridge between AI assistants that implement the Model Context Protocol (like Claude) and the Zoho Creator API. This allows AI assistants to perform operations on your Zoho Creator applications, such as fetching records, updating data, and more.

## Prerequisites

- [Node.js](https://nodejs.org/) (v18 or later)
- [npm](https://www.npmjs.com/) (v8 or later)
- Zoho Creator account with API access
- Git

## Getting Started

### Clone the Repository

```bash
git clone https://github.com/kamal157/zoho-creator-mcp.git
cd zoho-creator-mcp
```

### Install Dependencies

```bash
npm install
``` 

### Configuration

1. Create a `.env` file in the root directory with the following variables:

```
ZOHO_CLIENT_ID=your_client_id
ZOHO_CLIENT_SECRET=your_client_secret
ZOHO_REDIRECT_URI=http://localhost:3000/oauth/callback
ZOHO_ACCOUNT_OWNER=your_zoho_account_email
MCP_PORT=8000
ZOHO_ACCOUNTS_DOMAIN=https://accounts.zoho.in
ZOHO_API_DOMAIN=https://zohoapis.in/creator
```

Replace `your_client_id` and `your_client_secret` with your Zoho API credentials.

**Important:** 
- `ZOHO_ACCOUNT_OWNER` should be set to your Zoho account email address. This is crucial for API access.
- `ZOHO_ACCOUNTS_DOMAIN` and `ZOHO_API_DOMAIN` are region-specific. Modify them based on your Zoho Creator domain:
  - US: `https://accounts.zoho.com` and `https://zohoapis.com/creator`
  - India: `https://accounts.zoho.in` and `https://zohoapis.in/creator`
  - Europe: `https://accounts.zoho.eu` and `https://zohoapis.eu/creator`
  - Australia: `https://accounts.zoho.com.au` and `https://zohoapis.com.au/creator`
  - Others: Check Zoho documentation for your specific region

2. Alternatively, you can update the `.zoho-creator-credentials.json` file with your access token information.

### Setting Up Zoho Creator API Access

1. Go to the [Zoho Developer Console](https://api-console.zoho.in/)
2. Create a new client (Server Based-Client) 
3. Set the redirect URI to `http://localhost:3000/oauth/callback`
4. Make a note of the Client ID and Client Secret
5. Add these values to your `.env` file



## Running the Server

### Development Mode

```bash
npm run dev
```

This runs the server using ts-node for development purposes.

### Production Mode

```bash
npm run build
npm run stat
```

The build command compiles TypeScript to JavaScript in the `dist` directory, and start runs the compiled code.

### Authentication Flow

When you start the MCP server for the first time:

1. The server will detect that you don't have valid authentication tokens
2. It will initiate the OAuth flow by opening your browser to the Zoho authorization page
    ```bash
        node ./dist/zc-mcp-server.js -- auth

        or 

        npm run start -- auth
    ```
3. Copy the URL displayed on the Terminal and navigate,You'll be prompted to log in to your Zoho account and authorize the application
4. After authorization, Zoho will redirect to your callback URL (`http://localhost:3000/oauth/callback`)
5. The server will process the callback, extract the authorization code, and exchange it for access and refresh tokens
6. These tokens will be stored in the `.zoho-creator-credentials.json` file for future use

When you authorize the application, you'll see a screen like this:

![Zoho Creator Authorization Screen](zoho-creator-auth-screen.png)

The application will request permissions to access your Zoho Creator data, including:
- Get the list of dashboard applications
- Get the list of sections or components
- View records in a report
- Add/modify/delete records in Creator applications
- Read form metadata and options

## API Endpoints

The MCP server implements the following Model Context Protocol endpoints:

- `POST /mcp/list_tools`: List available tools for Zoho Creator
- `POST /mcp/call_tool`: Call a specific Zoho Creator tool

Additionally, the server provides:

- OAuth authentication flow for Zoho Creator
- Token refresh mechanism

## Available Tools

The server provides tools to interact with Zoho Creator, including:

- Fetching applications
- Getting forms and reports
- Retrieving, adding, updating, and deleting records
- Getting field metadata

## Authentication Process

The server automatically handles authentication through OAuth 2.0:

1. When first accessing protected endpoints, the server will attempt to use the stored tokens
2. If tokens are expired or missing, the server will initiate the OAuth flow
3. After successful authentication, tokens are saved for future use

![Zoho Creator MPC Authentication Flow](zoho-creator-mcp-auth-flow.png)

## Troubleshooting

### Common Issues

#### Token Expiration

If you encounter authentication errors, your token might be expired. The server should handle token refresh automatically, but you may need to re-authenticate occasionally.

#### API Limits

Be mindful of Zoho Creator API limits. If you encounter rate limit errors, reduce the frequency of your requests.



## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Integration with AI Assistants

### GitHub Copilot

To integrate with GitHub Copilot, add the following configuration to GitHub `settings.json` file:

```json
"zoho-creator-mcp":{        
    "type": "sse",
    "url": "http://localhost:8000/mcp"
},
```

### Claude IDE

To integrate with Claude IDE, add the following configuration to your Claude settings:

```json
"mcp": {
  "providers": {
    "zoho-creator-mcp": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://localhost:8000/mcp"
      ]
    }
  }
}
```



## Acknowledgments

- [Model Context Protocol](https://github.com/modelcontextprotocol) for the SDK
- [Zoho Creator](https://www.zoho.com/creator/) for the API
