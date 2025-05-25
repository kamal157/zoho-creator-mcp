#!/usr/bin/env node

import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import type { Request, Response } from 'express';
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';
import fetch from 'node-fetch';
import { URLSearchParams, URL } from 'url';
import http from 'http';

// --- Zoho Configuration ---
const ZOHO_CLIENT_ID = process.env.ZOHO_CLIENT_ID;
const ZOHO_CLIENT_SECRET = process.env.ZOHO_CLIENT_SECRET;
const ZOHO_REDIRECT_URI = process.env.ZOHO_REDIRECT_URI || "http://localhost:3000/oauth/callback";
const MCP_PORT = parseInt(process.env.MCP_PORT || "8000");

const ZOHO_ACCOUNTS_DOMAIN = process.env.ZOHO_ACCOUNTS_DOMAIN || "https://accounts.zoho.in";
const ZOHO_API_DOMAIN = process.env.ZOHO_API_DOMAIN || "https://zohoapis.in/creator";

const ZOHO_TOKEN_URL = `${ZOHO_ACCOUNTS_DOMAIN}/oauth/v2/token`;
const ZOHO_AUTH_URL = `${ZOHO_ACCOUNTS_DOMAIN}/oauth/v2/auth`;
const ZOHO_API_BASE_URL = `${ZOHO_API_DOMAIN}/v2.1`;

const credentialsPath = process.env.ZOHO_CREDENTIALS_PATH || path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../.zoho-creator-credentials.json",
);

interface ZohoCredentials {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
  issued_at: number;
}

// --- OAuth2 Authentication Functions ---

function getAuthorizationUrl(scopes: string[]): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: ZOHO_CLIENT_ID!,
    scope: scopes.join(","),
    redirect_uri: ZOHO_REDIRECT_URI,
    access_type: "offline",
    prompt: "consent",
  });
  return `${ZOHO_AUTH_URL}?${params.toString()}`;
}

async function exchangeCodeForTokens(code: string): Promise<ZohoCredentials | null> {
  try {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: ZOHO_CLIENT_ID!,
      client_secret: ZOHO_CLIENT_SECRET!,
      redirect_uri: ZOHO_REDIRECT_URI,
      code: code,
    });

    const response = await fetch(ZOHO_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
    });

    if (!response.ok) {
      console.error("Error exchanging code for tokens:", await response.text());
      return null;
    }
    const tokens = (await response.json()) as any;
    return {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
      issued_at: Math.floor(Date.now() / 1000),
    };
  } catch (error) {
    console.error("Exception during token exchange:", error);
    return null;
  }
}

async function refreshAccessToken(refreshToken: string): Promise<ZohoCredentials | null> {
  try {
    const params = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: ZOHO_CLIENT_ID!,
      client_secret: ZOHO_CLIENT_SECRET!,
      refresh_token: refreshToken,
    });

    const response = await fetch(ZOHO_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
    });

    if (!response.ok) {
      console.error("Error refreshing access token:", await response.text());
      return null;
    }
    const tokens = (await response.json()) as any;
    return {
      access_token: tokens.access_token,
      refresh_token: refreshToken,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
      issued_at: Math.floor(Date.now() / 1000),
    };
  } catch (error) {
    console.error("Exception during token refresh:", error);
    return null;
  }
}

function saveCredentials(credentials: ZohoCredentials): void {
  fs.writeFileSync(credentialsPath, JSON.stringify(credentials, null, 2));
  console.error(`Credentials saved to ${credentialsPath}`);
}

function loadCredentials(): ZohoCredentials | null {
  if (fs.existsSync(credentialsPath)) {
    const rawData = fs.readFileSync(credentialsPath, "utf-8");
    return JSON.parse(rawData) as ZohoCredentials;
  }
  return null;
}

async function getAccessToken(): Promise<string | null> {
  let credentials = loadCredentials();
  if (!credentials) {
    console.error("Credentials not found. Please run auth flow.");
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (credentials.issued_at + credentials.expires_in < now + 60) {
    console.error("Access token expired or nearing expiry. Refreshing...");
    if (!credentials.refresh_token) {
        console.error("No refresh token available. Please re-authenticate.");
        return null;
    }
    const newCredentials = await refreshAccessToken(credentials.refresh_token);
    if (newCredentials) {
      saveCredentials(newCredentials);
      credentials = newCredentials;
    } else {
      console.error("Failed to refresh access token.");
      return null;
    }
  }
  return credentials.access_token;
}

async function authenticateAndSave() {
  if (!ZOHO_CLIENT_ID || !ZOHO_CLIENT_SECRET) {
    console.error("ZOHO_CLIENT_ID and ZOHO_CLIENT_SECRET environment variables must be set.");
    process.exit(1);
  }

  // Request all necessary scopes for our tools
  const scopes = [
    "ZohoCreator.dashboard.READ",        // For reading applications
    "ZohoCreator.meta.application.READ", // For reading forms, reports, fields
    "ZohoCreator.report.READ",           // For fetching records from reports
    "ZohoCreator.form.CREATE",           // For adding records to forms
    "ZohoCreator.report.UPDATE",         // For updating records
    "ZohoCreator.report.DELETE",         // For deleting records
    "ZohoCreator.meta.form.READ"         // For fetching field metadata
  ];
  
  const authUrl = getAuthorizationUrl(scopes);
  console.log(`Please open this URL in your browser to authorize:\n${authUrl}`);

  const code = await new Promise<string | null>((resolve, reject) => {
    const redirectUri = new URL(ZOHO_REDIRECT_URI);
    const port = parseInt(redirectUri.port || "80");
    const hostname = redirectUri.hostname;

    const server = http.createServer(async (req, res) => {
      try {
        if (req.url) {
          const requestUrl = new URL(req.url, `http://${hostname}:${port}`);
          if (requestUrl.pathname === redirectUri.pathname) {
            const authCode = requestUrl.searchParams.get("code");
            if (authCode) {
              res.writeHead(200, { "Content-Type": "text/html" });
              res.end("<h1>Authentication Successful!</h1><p>You can close this window.</p>");
              resolve(authCode);
            } else {
              const error = requestUrl.searchParams.get("error");
              res.writeHead(400, { "Content-Type": "text/html" });
              res.end(`<h1>Authentication Failed</h1><p>Error: ${error || "Unknown error"}. Please try again.</p>`);
              resolve(null);
            }
          } else {
            res.writeHead(404);
            res.end("Not Found");
            resolve(null);
          }
        } else {
          res.writeHead(400);
          res.end("Bad Request");
          resolve(null);
        }
      } catch (e: any) {
        console.error("Error in callback server:", e);
        res.writeHead(500);
        res.end("Internal Server Error");
        resolve(null);
      } finally {
        server.close(() => {
          // console.error("Callback server closed.");
        });
      }
    });

    server.listen(port, hostname, () => {
      console.error(`Listening on ${hostname}:${port} for OAuth callback...`);
    });

    server.on('error', (err) => {
      console.error('Failed to start callback server:', err);
      reject(err);
    });
  });

  if (!code) {
    console.error("Failed to retrieve authorization code from callback.");
    process.exit(1);
  }

  const credentials = await exchangeCodeForTokens(code.trim());
  if (credentials) {
    saveCredentials(credentials);
    console.log("Authentication successful. Credentials saved.");
  } else {
    console.error("Authentication failed during token exchange.");
    process.exit(1);
  }
}

// --- Tool Definitions ---
const ZOHO_TOOLS = [
  {
    name: "get_applications",
    description: "Fetches all applications in your Zoho Creator account.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_name: { type: "string", description: "Filter applications by workspace name (optional)" },
      },
    },
  },
  {
    name: "get_forms",
    description: "Fetches all forms in a Zoho Creator application.",
    inputSchema: {
      type: "object",
      required: ["app_link_name"],
      properties: {
        app_link_name: { type: "string", description: "Link name of the application" },
      },
    },
  },
  {
    name: "get_reports",
    description: "Fetches all reports in a Zoho Creator application.",
    inputSchema: {
      type: "object",
      required: ["app_link_name"],
      properties: {
        app_link_name: { type: "string", description: "Link name of the application" },
      },
    },
  },
  {
    name: "get_fields",
    description: "Fetches field metadata from a form in a Zoho Creator application.",
    inputSchema: {
      type: "object",
      required: ["app_link_name", "form_link_name"],
      properties: {
        app_link_name: { type: "string", description: "Link name of the application" },
        form_link_name: { type: "string", description: "Link name of the form" },
      },
    },
  },
  {
    name: "get_records",
    description: "Fetches records from a report in a Zoho Creator application.",
    inputSchema: {
      type: "object",
      required: ["app_link_name", "report_link_name"],
      properties: {
        app_link_name: { type: "string", description: "Link name of the application" },
        report_link_name: { type: "string", description: "Link name of the report" },
        criteria: { type: "string", description: "Filter criteria (optional)" },
        from: { type: "integer", description: "Starting record index (optional)" },
        limit: { type: "integer", description: "Maximum number of records to return (optional, max 200)" },
        fields: { type: "array", items: { type: "string" }, description: "Fields to include in the response (optional)" },
      },
    },
  },
  {
    name: "add_record",
    description: "Adds a new record to a form in a Zoho Creator application.",
    inputSchema: {
      type: "object",
      required: ["app_link_name", "form_link_name", "data"],
      properties: {
        app_link_name: { type: "string", description: "Link name of the application" },
        form_link_name: { type: "string", description: "Link name of the form" },
        data: { type: "object", description: "Record data to add" },
      },
    },
  },
  {
    name: "update_record",
    description: "Updates a record in a report in a Zoho Creator application.",
    inputSchema: {
      type: "object",
      required: ["app_link_name", "report_link_name", "record_id", "data"],
      properties: {
        app_link_name: { type: "string", description: "Link name of the application" },
        report_link_name: { type: "string", description: "Link name of the report" },
        record_id: { type: "string", description: "ID of the record to update" },
        data: { type: "object", description: "Record data to update" },
      },
    },
  },
  {
    name: "delete_record",
    description: "Deletes or Remove a record from a report in a Zoho Creator application.",
    inputSchema: {
      type: "object",
      required: ["app_link_name", "report_link_name", "record_id"],
      properties: {
        app_link_name: { type: "string", description: "Link name of the application" },
        report_link_name: { type: "string", description: "Link name of the report" },
        record_id: { type: "string", description: "ID of the record to delete" },
      },
    },
  }
];

// Function to create and configure a new server instance for each request
function getServer() {
  const server = new Server(
    {
      name: "zoho-creator-mcp-server",
      version: "0.1.0",
    },
    {
      capabilities: {
        tools: {}, // Tools will be populated by ListTools handler
      },
    }
  );

  // Register request handlers
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: ZOHO_TOOLS };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const accessToken = await getAccessToken();

    if (!accessToken) {
      return {
        content: [{ type: "text", text: "Authentication required or failed. Please run the auth flow or check credentials." }],
        isError: true,
      };
    }

    try {
      // Standard API request headers
      const headers = {
        "Authorization": `Zoho-oauthtoken ${accessToken}`,
        "Accept": "application/json",
      };

      // Handle API errors uniformly
      const handleApiError = async (response: any) => {
        let errorText = "Unknown error";
        try {
          errorText = await response.text();
        } catch (e: any) {
          errorText = `Failed to get error text: ${e?.message || 'Unknown error'}`;
        }
        console.error(`Error from Zoho API (${response.status}): ${errorText}`);
        return {
          content: [{ type: "text", text: `API Error (${response.status}): ${errorText}` }],
          isError: true,
        };
      };

      // Get account owner name from credentials or environment
      const accountOwner = process.env.ZOHO_ACCOUNT_OWNER;
      if (!accountOwner || accountOwner === "test") {
        return {
          content: [{ type: "text", text: "Missing or invalid environment variable: ZOHO_ACCOUNT_OWNER. Please set it to your Zoho account owner/workspace name." }],
          isError: true,
        };
      }

      if (name === "get_applications") {
        const queryParams = new URLSearchParams();
        if (args?.workspace_name) {
          queryParams.append("workspace_name", args.workspace_name as string);
        }

        const url = `${ZOHO_API_BASE_URL}/meta/applications?${queryParams.toString()}`;
        const response = await fetch(url, {
          method: "GET",
          headers,
        });

        if (!response.ok) {
          return await handleApiError(response);
        }
        
        const data = await response.json();
        return {
          content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        };
      }
      else if (name === "get_forms") {
        if (!args?.app_link_name) {
          return {
            content: [{ type: "text", text: "Missing required parameter: app_link_name" }],
            isError: true,
          };
        }

        const appLinkName = args.app_link_name as string;
        const url = `${ZOHO_API_BASE_URL}/meta/${accountOwner}/${appLinkName}/forms`;
        
        const response = await fetch(url, {
          method: "GET",
          headers,
        });

        if (!response.ok) {
          return await handleApiError(response);
        }
        
        const data = await response.json();
        return {
          content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        };
      }
      else if (name === "get_reports") {
        if (!args?.app_link_name) {
          return {
            content: [{ type: "text", text: "Missing required parameter: app_link_name" }],
            isError: true,
          };
        }

        const appLinkName = args.app_link_name as string;
        const url = `${ZOHO_API_BASE_URL}/meta/${accountOwner}/${appLinkName}/reports`;
        
        const response = await fetch(url, {
          method: "GET",
          headers,
        });

        if (!response.ok) {
          return await handleApiError(response);
        }
        
        const data = await response.json();
        return {
          content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        };
      }
      else if (name === "get_fields") {
        if (!args?.app_link_name || !args?.form_link_name) {
          return {
            content: [{ type: "text", text: "Missing required parameters: app_link_name and/or form_link_name" }],
            isError: true,
          };
        }

        const appLinkName = args.app_link_name as string;
        const formLinkName = args.form_link_name as string;
        
        const url = `${ZOHO_API_BASE_URL}/meta/${accountOwner}/${appLinkName}/form/${formLinkName}/fields`;
        
        const response = await fetch(url, {
          method: "GET",
          headers,
        });

        if (!response.ok) {
          return await handleApiError(response);
        }
        
        const data = await response.json();
        return {
          content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        };
      }
      else if (name === "get_records") {
        if (!args?.app_link_name || !args?.report_link_name) {
          return {
            content: [{ type: "text", text: "Missing required parameters: app_link_name and/or report_link_name" }],
            isError: true,
          };
        }

        const appLinkName = args.app_link_name as string;
        const reportLinkName = args.report_link_name as string;
        
        // Build query parameters
        const queryParams = new URLSearchParams();
        
        if (args.criteria) {
          queryParams.append("criteria", args.criteria as string);
        }
        
        if (args.from !== undefined) {
          queryParams.append("from", (args.from as number).toString());
        }
        
        if (args.limit !== undefined) {
          queryParams.append("limit", (args.limit as number).toString());
        }
        
        // if (args.fields) {
        //   const fields = Array.isArray(args.fields) ? args.fields : [args.fields];
        //   queryParams.append("fields", JSON.stringify(fields));
        // }
        
        const url = `${ZOHO_API_BASE_URL}/data/${accountOwner}/${appLinkName}/report/${reportLinkName}?${queryParams.toString()}`;
        
        const response = await fetch(url, {
          method: "GET",
          headers,
        });

        if (!response.ok) {
          return await handleApiError(response);
        }
        
        const data = await response.json();
        return {
          content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        };
      }
      else if (name === "add_record") {
        if (!args?.app_link_name || !args?.form_link_name || !args?.data) {
          return {
            content: [{ type: "text", text: "Missing required parameters: app_link_name, form_link_name, and/or data" }],
            isError: true,
          };
        }

        const appLinkName = args.app_link_name as string;
        const formLinkName = args.form_link_name as string;
        const data = args.data as object;
        
        const url = `${ZOHO_API_BASE_URL}/data/${accountOwner}/${appLinkName}/form/${formLinkName}`;
        
        const payload = {
          data: [data],
          result: {
            fields: [],
            message: true
          }
        };
        
        const response = await fetch(url, {
          method: "POST",
          headers: {
            ...headers,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        });

        if (!response.ok) {
          return await handleApiError(response);
        }
        
        const responseData = await response.json();
        return {
          content: [{ type: "text", text: JSON.stringify(responseData, null, 2) }],
        };
      }
      else if (name === "update_record") {
        if (!args?.app_link_name || !args?.report_link_name || !args?.record_id || !args?.data) {
          return {
            content: [{ type: "text", text: "Missing required parameters: app_link_name, report_link_name, record_id, and/or data" }],
            isError: true,
          };
        }

        const appLinkName = args.app_link_name as string;
        const reportLinkName = args.report_link_name as string;
        const recordId = args.record_id as string;
        const data = args.data as object;
        
        const url = `${ZOHO_API_BASE_URL}/data/${accountOwner}/${appLinkName}/report/${reportLinkName}/${recordId}`;
        
        const payload = {
          data,
          result: {
            fields: [],
            message: true
          }
        };
        
        const response = await fetch(url, {
          method: "PATCH",
          headers: {
            ...headers,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        });

        if (!response.ok) {
          return await handleApiError(response);
        }
        
        const responseData = await response.json();
        return {
          content: [{ type: "text", text: JSON.stringify(responseData, null, 2) }],
        };
      }
      else if (name === "delete_record") {
        if (!args?.app_link_name || !args?.report_link_name || !args?.record_id) {
          return {
            content: [{ type: "text", text: "Missing required parameters: app_link_name, report_link_name, and/or record_id" }],
            isError: true,
          };
        }

        const appLinkName = args.app_link_name as string;
        const reportLinkName = args.report_link_name as string;
        const recordId = args.record_id as string;
        
        const url = `${ZOHO_API_BASE_URL}/data/${accountOwner}/${appLinkName}/report/${reportLinkName}/${recordId}`;
        
        const response = await fetch(url, {
          method: "DELETE",
          headers,
        });

        if (!response.ok) {
          return await handleApiError(response);
        }
        
        const responseData = await response.json();
        return {
          content: [{ type: "text", text: JSON.stringify(responseData, null, 2) }],
        };
      }
      else {
        return {
          content: [{ type: "text", text: `Tool '${name}' is not implemented.` }],
          isError: true,
        };
      }
    } catch (error: any) {
      console.error(`Error calling tool ${name}:`, error);
      return {
        content: [{ type: "text", text: `Failed to execute tool ${name}: ${error.message}` }],
        isError: true,
      };
    }
  });

  return server;
}

// --- Main Execution Logic ---
async function main() {
  if (process.argv.includes("auth")) {
    await authenticateAndSave();
    return; // Exit after auth
  }

  if (!ZOHO_CLIENT_ID || !ZOHO_CLIENT_SECRET) {
    console.error("ZOHO_CLIENT_ID and ZOHO_CLIENT_SECRET environment variables are required.");
    console.error("If you need to authenticate, run with the 'auth' argument: npm run dev -- auth");
    
    if (!fs.existsSync(credentialsPath)) {
      console.error(`Credentials file not found at ${credentialsPath}. Please run the 'auth' flow.`);
      process.exit(1);
    }
  }
  
  // Verify credentials work before starting the server
  const initialToken = await getAccessToken();
  if (!initialToken && !process.argv.includes("auth")) {
    console.error("Failed to obtain access token. Please ensure you have authenticated using the 'auth' command or check your credentials file.");
    process.exit(1);
  }

  console.log("Zoho Creator MCP Server starting...");
  
  // Setup Express server
  const app = express();
  app.use(express.json());

  // Handle POST requests for MCP
  app.post('/mcp', async (req: Request, res: Response) => {
    console.log('Received POST MCP request');
    
    try {
      // In stateless mode, create a new instance of transport and server for each request
      const server = getServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      
      res.on('close', () => {
        console.log('Request closed');
        transport.close();
        server.close();
      });
      
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error('Error handling MCP request:', error);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: 'Internal server error',
          },
          id: null,
        });
      }
    }
  });

  // Handle GET requests for MCP (method not allowed)
  app.get('/mcp', async (req: Request, res: Response) => {
    console.log('Received GET MCP request');
    res.writeHead(405).end(JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed."
      },
      id: null
    }));
  });

  // Handle DELETE requests for MCP (method not allowed)
  app.delete('/mcp', async (req: Request, res: Response) => {
    console.log('Received DELETE MCP request');
    res.writeHead(405).end(JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed."
      },
      id: null
    }));
  });

  // Start the server
  app.listen(MCP_PORT, () => {
    console.log(`Zoho Creator MCP Server listening on port ${MCP_PORT}`);
    console.log(`MCP endpoint: http://localhost:${MCP_PORT}/mcp`);
    console.log(`Use 'npm run dev -- auth' to authenticate.`);
  });
}

main().catch((error) => {
  console.error("Fatal error running Zoho Creator MCP Server:", error);
  process.exit(1);
});
