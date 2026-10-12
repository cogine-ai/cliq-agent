export declare const SQLITE_EXTENSION_NODE_VERSION: '24.21.0';
export declare const SQLITE_EXTENSION_HEADER_PINS: Readonly<{
  'sqlite3.h': '919e7f2e8ed1d8f56ac17b412b8971c76aa5d1a879752cc6058f75e7d5910e1d';
  'sqlite3ext.h': 'ac9645e5c9ff0cf176efdd6e75cb5e98f46295d38e02db5c4d208826a39ab4be';
}>;
export declare function verifiedSqliteExtensionIncludes(): Promise<string>;
