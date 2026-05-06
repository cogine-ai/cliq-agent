export const MODEL = 'anthropic/claude-sonnet-4.6';
export const DEFAULT_MODEL_PROVIDER = 'openrouter';
export const DEFAULT_MODEL_BASE_URL = 'https://openrouter.ai/api/v1';
export const OLLAMA_DEFAULT_BASE_URL = 'http://localhost:11434';
export const OLLAMA_DEFAULT_MODEL_HINT = 'qwen3:4b';
export const OLLAMA_DISCOVERY_TIMEOUT_MS = 2_000;
export const APP_DIR = '.cliq';
export const SESSION_FILE = 'session.json';
export const MAX_LOOPS = 24;
export const MAX_OUTPUT = 12_000;
export const MAX_STORED_TOOL_RESULT_CHARS = 12_000;
export const BASH_TIMEOUT_MS = 60_000;
export const MODEL_TIMEOUT_MS = 20_000;
export const OPENROUTER_TIMEOUT_MS = MODEL_TIMEOUT_MS;
export const SESSION_VERSION = 5;
export const DEFAULT_POLICY_MODE = 'auto';
export const READ_MAX_BYTES = 8_000;
export const LIST_MAX_ENTRIES = 200;
export const FIND_MAX_RESULTS = 200;
export const FIND_MAX_DEPTH = 12;
export const GREP_MAX_MATCHES = 200;
export const GREP_MAX_FILE_BYTES = 64_000;

// Transactional workspace runtime env overrides (v0.8). Resolution precedence:
// CLI flag > env var > workspace config > built-in default.
export const CLIQ_TX_MODE = process.env.CLIQ_TX_MODE;
export const CLIQ_TX_APPLY_POLICY = process.env.CLIQ_TX_APPLY_POLICY;
export const CLIQ_TX_BASH_POLICY = process.env.CLIQ_TX_BASH_POLICY;
export const CLIQ_TX_HEADLESS = process.env.CLIQ_TX_HEADLESS === '1';
