#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import fetch from 'node-fetch';

const API_BASE_URL = 'https://httpworkbench.com/api/guest/instances';

class HTTPWorkbenchServer {
  constructor() {
    this.server = new Server(
      {
        name: 'httpworkbench-mcp',
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();

    // Error handling
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'httpworkbench_create_instance',
          description: 'Create a new HTTPWorkbench instance with custom HTTP response. Returns an instance ID and URL for testing SSRF, XXE, etc.',
          inputSchema: {
            type: 'object',
            properties: {
              response: {
                type: 'string',
                description: 'Custom HTTP response (full raw HTTP response including headers). Example: "HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\n\\r\\n<h1>Hello</h1>"',
              },
              description: {
                type: 'string',
                description: 'Optional description for this instance to help track its purpose',
              },
            },
            required: ['response'],
          },
        },
        {
          name: 'httpworkbench_update_instance',
          description: 'Update the HTTP response of an existing HTTPWorkbench instance.',
          inputSchema: {
            type: 'object',
            properties: {
              instance_id: {
                type: 'string',
                description: 'Instance ID returned by create_instance',
              },
              response: {
                type: 'string',
                description: 'New custom HTTP response (full raw HTTP response including headers)',
              },
            },
            required: ['instance_id', 'response'],
          },
        },
        {
          name: 'httpworkbench_get_logs',
          description: 'Get all HTTP requests received by an HTTPWorkbench instance.',
          inputSchema: {
            type: 'object',
            properties: {
              instance_id: {
                type: 'string',
                description: 'Instance ID to check for requests',
              },
            },
            required: ['instance_id'],
          },
        },
        {
          name: 'httpworkbench_poll_logs',
          description: 'Poll HTTPWorkbench instance logs for new requests with timeout. Useful for waiting for SSRF callbacks.',
          inputSchema: {
            type: 'object',
            properties: {
              instance_id: {
                type: 'string',
                description: 'Instance ID to monitor',
              },
              timeout_seconds: {
                type: 'number',
                description: 'How long to wait for new requests (default: 30)',
                default: 30,
              },
              poll_interval: {
                type: 'number',
                description: 'Seconds between polls (default: 2)',
                default: 2,
              },
            },
            required: ['instance_id'],
          },
        },
        {
          name: 'httpworkbench_create_ssrf_payload',
          description: 'Create a pre-configured HTTPWorkbench instance optimized for SSRF testing with common payloads.',
          inputSchema: {
            type: 'object',
            properties: {
              payload_type: {
                type: 'string',
                enum: ['html', 'xml', 'json', 'text', 'redirect', 'cors'],
                description: 'Type of SSRF payload to create',
              },
              custom_content: {
                type: 'string',
                description: 'Custom content to include in the response (optional)',
              },
            },
            required: ['payload_type'],
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      switch (request.params.name) {
        case 'httpworkbench_create_instance':
          return await this.createInstance(request.params.arguments);
        case 'httpworkbench_update_instance':
          return await this.updateInstance(request.params.arguments);
        case 'httpworkbench_get_logs':
          return await this.getLogs(request.params.arguments);
        case 'httpworkbench_poll_logs':
          return await this.pollLogs(request.params.arguments);
        case 'httpworkbench_create_ssrf_payload':
          return await this.createSSRFPayload(request.params.arguments);
        default:
          throw new Error(`Unknown tool: ${request.params.name}`);
      }
    });
  }

  async makeRequest(endpoint, method = 'GET', body = null) {
    const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;

    const options = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'HTTPWorkbench-MCP/1.0',
        'Accept': '*/*',
        'Origin': 'https://httpworkbench.com',
        'Referer': 'https://httpworkbench.com/',
      },
    };

    if (body && (method === 'POST' || method === 'PUT')) {
      options.body = JSON.stringify(body);
    }

    try {
      const response = await fetch(url, options);

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTPWorkbench API error (${response.status}): ${errorText}`);
      }

      const data = await response.json();
      return data;
    } catch (error) {
      if (error.message.includes('HTTPWorkbench API error')) {
        throw error;
      }
      throw new Error(`Network error: ${error.message}`);
    }
  }

  async createInstance(args) {
    try {
      const payload = {
        kind: 'static',
        raw: args.response
      };

      const response = await this.makeRequest('', 'POST', payload);

      const instanceUrl = `${response.id}.instances.httpworkbench.com`;
      const httpsUrl = `https://${instanceUrl}`;
      const httpUrl = `http://${instanceUrl}`;

      const expiresAt = new Date(response.expiresAt).toLocaleString();

      let result = `🚀 HTTPWorkbench instance created successfully!\n\n`;
      result += `📋 **Instance Details:**\n`;
      result += `   🆔 ID: ${response.id}\n`;
      result += `   🌐 URL: ${instanceUrl}\n`;
      result += `   🔗 HTTPS: ${httpsUrl}\n`;
      result += `   🔗 HTTP: ${httpUrl}\n`;
      result += `   ⏰ Expires: ${expiresAt}\n\n`;

      if (args.description) {
        result += `📝 Description: ${args.description}\n\n`;
      }

      result += `💡 **Usage:**\n`;
      result += `   • Test SSRF: Use ${httpsUrl} in vulnerable parameters\n`;
      result += `   • Monitor requests: Use httpworkbench_get_logs with ID ${response.id}\n`;
      result += `   • Update response: Use httpworkbench_update_instance\n\n`;

      result += `🔧 **Response configured:**\n`;
      result += `\`\`\`http\n${args.response}\n\`\`\``;

      return {
        content: [
          {
            type: 'text',
            text: result,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `❌ Error creating HTTPWorkbench instance: ${error.message}`,
          },
        ],
      };
    }
  }

  async updateInstance(args) {
    try {
      const payload = {
        kind: 'static',
        raw: args.response,
        webhookIds: []
      };

      await this.makeRequest(`/${args.instance_id}`, 'PUT', payload);

      const instanceUrl = `${args.instance_id}.instances.httpworkbench.com`;

      let result = `✅ HTTPWorkbench instance updated successfully!\n\n`;
      result += `🆔 Instance: ${args.instance_id}\n`;
      result += `🌐 URL: ${instanceUrl}\n\n`;
      result += `🔧 **New response:**\n`;
      result += `\`\`\`http\n${args.response}\n\`\`\``;

      return {
        content: [
          {
            type: 'text',
            text: result,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `❌ Error updating HTTPWorkbench instance: ${error.message}`,
          },
        ],
      };
    }
  }

  async getLogs(args) {
    try {
      const response = await this.makeRequest(`/${args.instance_id}`);

      const instance = response.instance;
      const logs = response.logs || [];

      const instanceUrl = `${instance.id}.instances.httpworkbench.com`;
      const expiresAt = new Date(instance.expiresAt).toLocaleString();

      let result = `📊 HTTPWorkbench logs for instance ${instance.id}\n\n`;
      result += `🌐 URL: ${instanceUrl}\n`;
      result += `⏰ Expires: ${expiresAt}\n`;
      result += `📈 Total requests: ${logs.length}\n\n`;

      if (logs.length === 0) {
        result += `🔍 No requests received yet.\n\n`;
        result += `💡 Test the instance by visiting: https://${instanceUrl}`;
      } else {
        result += `📝 **Recent requests:**\n\n`;

        // Show last 10 requests (most recent first)
        const recentLogs = logs.slice(-10).reverse();

        recentLogs.forEach((log, index) => {
          const timestamp = new Date(log.timestamp).toLocaleString();
          const requestLines = log.raw.split('\r\n');
          const requestLine = requestLines[0]; // First line: GET /path HTTP/1.1

          result += `【${index + 1}】 ${timestamp}\n`;
          result += `   🌍 IP: ${log.address}\n`;
          result += `   📡 Request: ${requestLine}\n`;

          // Extract interesting headers
          const headers = requestLines.slice(1).filter(line => line.includes(':'));
          const userAgent = headers.find(h => h.toLowerCase().startsWith('user-agent:'));
          const referer = headers.find(h => h.toLowerCase().startsWith('referer:'));

          if (userAgent) {
            result += `   🖥️  User-Agent: ${userAgent.split(': ')[1]}\n`;
          }
          if (referer) {
            result += `   🔗 Referer: ${referer.split(': ')[1]}\n`;
          }

          result += `\n`;
        });

        if (logs.length > 10) {
          result += `... and ${logs.length - 10} more requests\n\n`;
        }
      }

      return {
        content: [
          {
            type: 'text',
            text: result,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `❌ Error getting HTTPWorkbench logs: ${error.message}`,
          },
        ],
      };
    }
  }

  async pollLogs(args) {
    const timeoutSeconds = args.timeout_seconds || 30;
    const pollInterval = args.poll_interval || 2;
    const maxPolls = Math.ceil(timeoutSeconds / pollInterval);

    try {
      // Get initial count
      const initialResponse = await this.makeRequest(`/${args.instance_id}`);
      const initialCount = (initialResponse.logs || []).length;
      const instanceUrl = `${args.instance_id}.instances.httpworkbench.com`;

      let result = `⏳ Polling HTTPWorkbench instance ${args.instance_id} for new requests...\n\n`;
      result += `🌐 URL: ${instanceUrl}\n`;
      result += `⏰ Timeout: ${timeoutSeconds}s (polling every ${pollInterval}s)\n`;
      result += `📊 Initial requests: ${initialCount}\n\n`;

      // Poll for new requests
      for (let i = 0; i < maxPolls; i++) {
        await new Promise(resolve => setTimeout(resolve, pollInterval * 1000));

        const currentResponse = await this.makeRequest(`/${args.instance_id}`);
        const currentLogs = currentResponse.logs || [];
        const newRequestsCount = currentLogs.length - initialCount;

        if (newRequestsCount > 0) {
          // Found new requests!
          const newRequests = currentLogs.slice(initialCount);

          result += `🎉 **${newRequestsCount} new request(s) detected!**\n\n`;

          newRequests.forEach((log, index) => {
            const timestamp = new Date(log.timestamp).toLocaleString();
            const requestLines = log.raw.split('\r\n');
            const requestLine = requestLines[0];

            result += `【${index + 1}】 ${timestamp}\n`;
            result += `   🌍 IP: ${log.address}\n`;
            result += `   📡 Request: ${requestLine}\n`;

            // Extract interesting headers
            const headers = requestLines.slice(1).filter(line => line.includes(':'));
            const userAgent = headers.find(h => h.toLowerCase().startsWith('user-agent:'));

            if (userAgent) {
              result += `   🖥️  User-Agent: ${userAgent.split(': ')[1]}\n`;
            }

            result += `\n`;
          });

          return {
            content: [
              {
                type: 'text',
                text: result,
              },
            ],
          };
        }

        // Update progress
        const elapsed = (i + 1) * pollInterval;
        if (elapsed % 10 === 0) { // Update every 10 seconds
          result += `⏱️  ${elapsed}s elapsed, still waiting...\n`;
        }
      }

      // Timeout reached
      result += `⏰ **Timeout reached** (${timeoutSeconds}s)\n`;
      result += `📊 No new requests detected during polling period.\n\n`;
      result += `💡 You can manually check logs with: httpworkbench_get_logs instance_id="${args.instance_id}"`;

      return {
        content: [
          {
            type: 'text',
            text: result,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `❌ Error polling HTTPWorkbench logs: ${error.message}`,
          },
        ],
      };
    }
  }

  async createSSRFPayload(args) {
    let response;
    const customContent = args.custom_content || '';

    switch (args.payload_type) {
      case 'html':
        response = `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nAccess-Control-Allow-Origin: *\r\n\r\n<html><body><h1>SSRF Success</h1><p>Server reached via SSRF</p>${customContent}</body></html>`;
        break;

      case 'xml':
        response = `HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nAccess-Control-Allow-Origin: *\r\n\r\n<?xml version="1.0"?><root><message>SSRF Success</message><data>${customContent}</data></root>`;
        break;

      case 'json':
        response = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{"success":true,"message":"SSRF Success","data":"${customContent}"}`;
        break;

      case 'text':
        response = `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\n\r\nSSRF Success - Server reachable\n${customContent}`;
        break;

      case 'redirect':
        const redirectUrl = customContent || 'https://evil.com/';
        response = `HTTP/1.1 302 Found\r\nLocation: ${redirectUrl}\r\nAccess-Control-Allow-Origin: *\r\n\r\n`;
        break;

      case 'cors':
        response = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: *\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Allow-Credentials: true\r\n\r\n{"cors":"enabled","message":"CORS bypass success","data":"${customContent}"}`;
        break;

      default:
        throw new Error(`Unknown payload type: ${args.payload_type}`);
    }

    // Create the instance
    const createResult = await this.createInstance({
      response,
      description: `SSRF ${args.payload_type} payload${customContent ? ` - ${customContent}` : ''}`
    });

    return createResult;
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('HTTPWorkbench MCP server running on stdio');
  }
}

const server = new HTTPWorkbenchServer();
server.run().catch(console.error);
