export type ChatMessage = {
  role: 'system' | 'user' | 'assistant';
  content: string;
};

export type ModelClient = {
  complete(messages: ChatMessage[]): Promise<string>;
};
