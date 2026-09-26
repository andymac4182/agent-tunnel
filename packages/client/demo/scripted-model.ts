/**
 * A deterministic stand-in for a language model, for the adapter demo and the
 * peer tests: **no API key, no network, no real LLM**.
 *
 * It is `ai`'s own `MockLanguageModelV4` (from `ai/test`) driven by a script:
 * each generation step returns the next scripted tool call, and once the script
 * is exhausted it answers with text summarising the tool results it was shown.
 * The framework under test — `generateText`'s tool loop, or a Mastra `Agent` —
 * does everything else for real: it offers the tools, validates the scripted
 * input against each tool's schema, calls `execute`, and feeds the result back
 * into the next step's prompt. That is the part worth demonstrating; which
 * tool to call is the only decision the model makes, and here the script makes
 * it.
 */

import type { LanguageModelV4CallOptions, LanguageModelV4GenerateResult } from '@ai-sdk/provider';
import { MockLanguageModelV4 } from 'ai/test';

export interface ScriptedCall {
  toolName: string;
  input: Record<string, unknown>;
}

export interface ScriptedModel {
  model: MockLanguageModelV4;
  /** The tool names the framework offered on each step, in order. */
  offered: string[][];
}

const usage = {
  inputTokens: { total: 0, noCache: 0, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 0, text: 0, reasoning: 0 },
};

/**
 * The tool results the framework fed back, read from the prompt: what a real
 * model would have "seen". Returned as tool name plus a JSON rendering.
 */
export function toolResultsIn(options: LanguageModelV4CallOptions): { toolName: string; output: string }[] {
  const seen: { toolName: string; output: string }[] = [];
  for (const message of options.prompt) {
    if (message.role !== 'tool') {
      continue;
    }
    for (const part of message.content) {
      if (part.type === 'tool-result') {
        const output = part.output;
        const rendered =
          output.type === 'text' || output.type === 'error-text'
            ? output.value
            : output.type === 'json' || output.type === 'error-json'
              ? JSON.stringify(output.value)
              : output.type;
        seen.push({ toolName: part.toolName, output: rendered });
      }
    }
  }
  return seen;
}

export function scriptedModel(script: ScriptedCall[], finalText?: (options: LanguageModelV4CallOptions) => string): ScriptedModel {
  const offered: string[][] = [];
  let step = 0;
  const model = new MockLanguageModelV4({
    provider: 'agent-tunnel-demo',
    modelId: 'scripted',
    doGenerate: async (options: LanguageModelV4CallOptions): Promise<LanguageModelV4GenerateResult> => {
      offered.push((options.tools ?? []).map((tool) => tool.name));
      const next = script[step];
      step += 1;
      if (next !== undefined) {
        return {
          content: [
            { type: 'tool-call', toolCallId: `call-${step}`, toolName: next.toolName, input: JSON.stringify(next.input) },
          ],
          finishReason: { unified: 'tool-calls', raw: 'tool_calls' },
          usage,
          warnings: [],
        };
      }
      const text = finalText?.(options) ?? `Saw ${toolResultsIn(options).length} tool results.`;
      return {
        content: [{ type: 'text', text }],
        finishReason: { unified: 'stop', raw: 'stop' },
        usage,
        warnings: [],
      };
    },
  });
  return { model, offered };
}
