#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import fetch from 'node-fetch';

const API_BASE_URL = 'https://oathnet.org/api/service';
const API_KEY = process.env.OATHNET_API_KEY || '75e7a6b3f8fe3bc0bb6427efcbf45be98b2902355cfd74722f38f8ea637f3fd9';

class OathNetServer {
  constructor() {
    this.server = new Server(
      {
        name: 'oathnet-mcp',
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
          name: 'oathnet_init_search_session',
          description: 'Initialize a search session for OathNet API to optimize quota usage. Returns a session ID for subsequent searches.',
          inputSchema: {
            type: 'object',
            properties: {
              query: {
                type: 'string',
                description: 'Initial query to initialize the session (domain, email, IP, username, etc.)',
              },
            },
            required: ['query'],
          },
        },
        {
          name: 'oathnet_search_credentials',
          description: 'Search for credentials and data breaches related to a domain or email pattern. Finds leaked credentials, passwords, and personal data.',
          inputSchema: {
            type: 'object',
            properties: {
              query: {
                type: 'string',
                description: 'Search query - can be domain (elweth.fr), email pattern (*@elweth.fr), or specific email',
              },
              search_id: {
                type: 'string',
                description: 'Optional session ID from init_search_session to save quota',
              },
            },
            required: ['query'],
          },
        },
        {
          name: 'oathnet_search_stealer_logs',
          description: 'Search stealer database for credentials, cookies, and browser data stolen by malware. Often contains more recent data than breaches.',
          inputSchema: {
            type: 'object',
            properties: {
              query: {
                type: 'string',
                description: 'Search query - domain, email, or username to find in stealer logs',
              },
              search_id: {
                type: 'string',
                description: 'Optional session ID from init_search_session to save quota',
              },
            },
            required: ['query'],
          },
        },
        {
          name: 'oathnet_search_subdomains',
          description: 'Search for subdomains and related infrastructure of a target domain. Useful for reconnaissance and attack surface mapping.',
          inputSchema: {
            type: 'object',
            properties: {
              domain: {
                type: 'string',
                description: 'Target domain to find subdomains for (e.g., elweth.fr)',
              },
              search_id: {
                type: 'string',
                description: 'Optional session ID from init_search_session to save quota',
              },
            },
            required: ['domain'],
          },
        },
        {
          name: 'oathnet_multi_search',
          description: 'Perform comprehensive search across breaches, stealers, and OSINT for a target. Combines credential search, stealer logs, and subdomain enumeration.',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Target domain or organization to investigate comprehensively',
              },
            },
            required: ['target'],
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      switch (request.params.name) {
        case 'oathnet_init_search_session':
          return await this.initSearchSession(request.params.arguments);
        case 'oathnet_search_credentials':
          return await this.searchCredentials(request.params.arguments);
        case 'oathnet_search_stealer_logs':
          return await this.searchStealerLogs(request.params.arguments);
        case 'oathnet_search_subdomains':
          return await this.searchSubdomains(request.params.arguments);
        case 'oathnet_multi_search':
          return await this.multiSearch(request.params.arguments);
        default:
          throw new Error(`Unknown tool: ${request.params.name}`);
      }
    });
  }

  // Utility function to normalize API response data to array format
  normalizeResponseData(responseData) {
    if (!responseData) return [];

    // OathNet API structure: response.data.items
    if (responseData.items && Array.isArray(responseData.items)) {
      return responseData.items;
    }

    if (Array.isArray(responseData)) {
      return responseData;
    }

    if (responseData.results && Array.isArray(responseData.results)) {
      return responseData.results;
    }

    if (responseData.data && Array.isArray(responseData.data)) {
      return responseData.data;
    }

    if (typeof responseData === 'object' && responseData !== null) {
      // Single object result or unexpected structure
      return [responseData];
    }

    return [];
  }

  async makeRequest(endpoint, method = 'GET', body = null, params = {}) {
    const url = new URL(`${API_BASE_URL}${endpoint}`);

    // Add query parameters
    Object.keys(params).forEach(key => {
      if (params[key] !== undefined && params[key] !== null) {
        url.searchParams.append(key, params[key]);
      }
    });

    const options = {
      method,
      headers: {
        'x-api-key': API_KEY,
        'Content-Type': 'application/json',
        'User-Agent': 'OathNet-MCP/1.0',
      },
    };

    if (body && (method === 'POST' || method === 'PUT')) {
      options.body = JSON.stringify(body);
    }

    try {
      const response = await fetch(url.toString(), options);

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OathNet API error (${response.status}): ${errorText}`);
      }

      const data = await response.json();
      return data;
    } catch (error) {
      if (error.message.includes('OathNet API error')) {
        throw error;
      }
      throw new Error(`Network error: ${error.message}`);
    }
  }

  async initSearchSession(args) {
    try {
      const response = await this.makeRequest('/search/init', 'POST', {
        query: args.query,
      });

      return {
        content: [
          {
            type: 'text',
            text: `🔐 Search session initialized successfully!\n\n` +
                  `Session ID: ${response.data?.session?.id || 'N/A'}\n` +
                  `Query: ${args.query}\n\n` +
                  `ℹ️ Use this session ID in subsequent searches to save quota.\n` +
                  `Session valid for 60 minutes.`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `❌ Error initializing search session: ${error.message}`,
          },
        ],
      };
    }
  }

  async searchCredentials(args) {
    try {
      const params = { q: args.query };
      if (args.search_id) {
        params.search_id = args.search_id;
      }

      const response = await this.makeRequest('/v2/breach/search', 'GET', null, params);
      const dataArray = this.normalizeResponseData(response.data);

      if (dataArray.length === 0) {
        return {
          content: [
            {
              type: 'text',
              text: `🔍 No credentials found in breach database for: ${args.query}`,
            },
          ],
        };
      }

      let result = `🚨 Credentials found in breach database for: ${args.query}\n\n`;
      result += `📊 Total results: ${dataArray.length}\n\n`;

      dataArray.forEach((item, index) => {
        result += `【${index + 1}】\n`;
        if (item.username) result += `   👤 Username: ${item.username}\n`;
        if (item.password) result += `   🔑 Password: ${item.password}\n`;
        if (item.url) result += `   🌐 URL: ${item.url}\n`;
        if (item.domain && Array.isArray(item.domain)) result += `   🌍 Domain: ${item.domain.join(', ')}\n`;
        if (item.subdomain && Array.isArray(item.subdomain)) result += `   🌐 Subdomain: ${item.subdomain.join(', ')}\n`;
        if (item.email_domains && Array.isArray(item.email_domains)) result += `   📧 Email domains: ${item.email_domains.join(', ')}\n`;
        if (item.log_id) result += `   📁 Log ID: ${item.log_id.substring(0, 16)}...\n`;
        if (item.pwned_at) result += `   📅 Pwned: ${item.pwned_at}\n`;
        if (item.indexed_at) result += `   📅 Indexed: ${item.indexed_at}\n`;
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
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `❌ Error searching credentials: ${error.message}`,
          },
        ],
      };
    }
  }

  async searchStealerLogs(args) {
    try {
      const params = { q: args.query };
      if (args.search_id) {
        params.search_id = args.search_id;
      }

      const response = await this.makeRequest('/v2/stealer/search', 'GET', null, params);
      const dataArray = this.normalizeResponseData(response.data);

      if (dataArray.length === 0) {
        return {
          content: [
            {
              type: 'text',
              text: `🔍 No data found in stealer logs for: ${args.query}`,
            },
          ],
        };
      }

      let result = `🦠 Stealer logs found for: ${args.query}\n\n`;
      result += `📊 Total results: ${dataArray.length}\n\n`;

      dataArray.forEach((item, index) => {
        result += `【${index + 1}】\n`;
        if (item.username) result += `   👤 Username: ${item.username}\n`;
        if (item.password) result += `   🔑 Password: ${item.password}\n`;
        if (item.url) result += `   🌐 URL: ${item.url}\n`;
        if (item.domain && Array.isArray(item.domain)) result += `   🌍 Domain: ${item.domain.join(', ')}\n`;
        if (item.subdomain && Array.isArray(item.subdomain)) result += `   🌐 Subdomain: ${item.subdomain.join(', ')}\n`;
        if (item.email_domains && Array.isArray(item.email_domains)) result += `   📧 Email domains: ${item.email_domains.join(', ')}\n`;
        if (item.path && Array.isArray(item.path)) result += `   📁 Path: ${item.path.join(', ')}\n`;
        if (item.log_id) result += `   🦠 Log ID: ${item.log_id.substring(0, 16)}...\n`;
        if (item.pwned_at) result += `   📅 Pwned: ${item.pwned_at}\n`;
        if (item.indexed_at) result += `   📅 Indexed: ${item.indexed_at}\n`;
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
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `❌ Error searching stealer logs: ${error.message}`,
          },
        ],
      };
    }
  }

  async searchSubdomains(args) {
    try {
      const domain = args.domain.replace(/^https?:\/\//, '').replace(/\/$/, '');

      let allSubdomains = new Set();
      let sessionId = args.search_id;

      // Initialize session if not provided
      if (!sessionId) {
        try {
          const sessionResponse = await this.makeRequest('/search/init', 'POST', {
            query: domain,
          });
          sessionId = sessionResponse.data?.session?.id;
        } catch (e) {
          // Continue without session if init fails
        }
      }

      // Primary source: dedicated stealer-subdomain endpoint (returns the full list).
      try {
        const params = { domain };
        if (sessionId) params.search_id = sessionId;
        const resp = await this.makeRequest('/v2/stealer/subdomain', 'GET', null, params);
        const subs = resp.data?.data?.subdomains
          ?? resp.data?.subdomains
          ?? [];
        if (Array.isArray(subs)) {
          subs.forEach(sub => { if (sub && typeof sub === 'string') allSubdomains.add(sub); });
        }
      } catch (error) {
        console.error(`stealer/subdomain failed:`, error.message);
      }

      // Supplement: harvest hostnames from breach + stealer record fields.
      const searches = [`*.${domain}`, domain, `${domain}/*`];
      for (const searchQuery of searches) {
        try {
          const params = { q: searchQuery };
          if (sessionId) params.search_id = sessionId;

          const harvest = (items) => {
            items.forEach(item => {
              if (item.url) {
                try {
                  const u = new URL(item.url);
                  if (u.hostname.includes(domain)) allSubdomains.add(u.hostname);
                } catch (_) {}
              }
              if (Array.isArray(item.subdomain)) {
                item.subdomain.forEach(s => { if (s && s.includes(domain)) allSubdomains.add(s); });
              }
              if (Array.isArray(item.domain)) {
                item.domain.forEach(d => { if (d && d.includes(domain)) allSubdomains.add(d); });
              }
              if (Array.isArray(item.email_domains)) {
                item.email_domains.forEach(e => { if (e && e.includes(domain)) allSubdomains.add(e); });
              }
              if (item.username && item.username.includes('@')) {
                const ed = item.username.split('@')[1];
                if (ed && ed.includes(domain)) allSubdomains.add(ed);
              }
            });
          };

          try {
            const breachResponse = await this.makeRequest('/v2/breach/search', 'GET', null, params);
            harvest(this.normalizeResponseData(breachResponse.data));
          } catch (e) { /* tolerate per-source failure */ }

          try {
            const stealerResponse = await this.makeRequest('/v2/stealer/search', 'GET', null, params);
            harvest(this.normalizeResponseData(stealerResponse.data));
          } catch (e) { /* tolerate per-source failure */ }
        } catch (error) {
          console.error(`Search failed for ${searchQuery}:`, error.message);
        }
      }

      // Drop entries that aren't actually subdomains of the target (e.g. the bare domain or unrelated hosts).
      const subdomainsList = Array.from(allSubdomains)
        .filter(s => s && (s === domain || s.endsWith(`.${domain}`)))
        .sort();

      if (subdomainsList.length === 0) {
        return {
          content: [
            {
              type: 'text',
              text: `🔍 No subdomains found for: ${domain}`,
            },
          ],
        };
      }

      let result = `🌐 Subdomains discovered for: ${domain}\n\n`;
      result += `📊 Total subdomains: ${subdomainsList.length}\n\n`;

      subdomainsList.forEach((subdomain, index) => {
        result += `${index + 1}. ${subdomain}\n`;
      });

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
            text: `❌ Error searching subdomains: ${error.message}`,
          },
        ],
      };
    }
  }

  async multiSearch(args) {
    try {
      const target = args.target.replace(/^https?:\/\//, '').replace(/\/$/, '');

      let result = `🎯 Comprehensive OathNet search for: ${target}\n\n`;

      // Initialize session
      let sessionId;
      try {
        const sessionResponse = await this.makeRequest('/search/init', 'POST', {
          query: target,
        });
        sessionId = sessionResponse.data?.session?.id;
        result += `🔐 Session initialized: ${sessionId}\n\n`;
      } catch (e) {
        result += `⚠️ Could not initialize session, using direct searches\n\n`;
      }

      // 1. Search credentials in breach database
      result += `📊 BREACH DATABASE SEARCH\n`;
      result += `${'='.repeat(40)}\n`;
      try {
        const credSearchResult = await this.searchCredentials({
          query: `*@${target}`,
          search_id: sessionId
        });
        result += credSearchResult.content[0].text.replace(/^🚨[^]*?📊/, '📊') + '\n\n';
      } catch (e) {
        result += `❌ Breach search failed: ${e.message}\n\n`;
      }

      // 2. Search stealer logs
      result += `🦠 STEALER LOGS SEARCH\n`;
      result += `${'='.repeat(40)}\n`;
      try {
        const stealerSearchResult = await this.searchStealerLogs({
          query: target,
          search_id: sessionId
        });
        result += stealerSearchResult.content[0].text.replace(/^🦠[^]*?📊/, '📊') + '\n\n';
      } catch (e) {
        result += `❌ Stealer search failed: ${e.message}\n\n`;
      }

      // 3. Search subdomains
      result += `🌐 SUBDOMAIN ENUMERATION\n`;
      result += `${'='.repeat(40)}\n`;
      try {
        const subdomainSearchResult = await this.searchSubdomains({
          domain: target,
          search_id: sessionId
        });
        result += subdomainSearchResult.content[0].text.replace(/^🌐[^]*?📊/, '📊') + '\n\n';
      } catch (e) {
        result += `❌ Subdomain search failed: ${e.message}\n\n`;
      }

      result += `✅ Comprehensive search completed for ${target}`;

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
            text: `❌ Error in multi-search: ${error.message}`,
          },
        ],
      };
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('OathNet MCP server running on stdio');
  }
}

const server = new OathNetServer();
server.run().catch(console.error);
