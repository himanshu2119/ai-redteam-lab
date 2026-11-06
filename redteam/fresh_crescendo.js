// Wraps promptfoo's crescendo strategy so EVERY attack starts a fresh conversation.
//
// Why: promptfoo builds one crescendo object per test and reuses it for every --repeat,
// and crescendo only creates its conversation id in its constructor. So in the first
// "before" run, repeats 2 and 3 of each M test continued repeat 1's conversation.
// Here a new crescendo instance is created for each call (= each test x repeat).
//
// It also tags the final response with which conversation it was, so the judge
// (conversation_judge.py) can rebuild the whole conversation from the logs.
const path = require('path');
const { loadApiProvider } = require('promptfoo');

// require('promptfoo') is a separate copy from the CLI's, without the CLI's base path, so it
// would resolve "file://judge_provider.py" against the repo root. Make such paths absolute.
function absolutize(value) {
  if (typeof value === 'string' && value.startsWith('file://')) {
    const rest = value.slice('file://'.length);
    return path.isAbsolute(rest) ? value : `file://${path.join(__dirname, rest)}`;
  }
  if (Array.isArray(value)) return value.map(absolutize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, absolutize(v)]));
  }
  return value;
}

// Crescendo's internal refusal / progress scoring normally uses the config's defaultTest grader,
// found through the CLI's run state. That state is empty in this copy, so crescendo would fall
// back to promptfoo's default OpenAI model (no key here -> every check silently fails, so no
// backtracking and no early stop). Give it the same grader the original "before" run used:
// judge_provider.py with role "grader" (calls without an attack_id go to local qwen2.5:3b).
const SCORING_PROVIDER = {
  id: `file://${path.join(__dirname, 'judge_provider.py')}`,
  config: { role: 'grader', temperature: 0 },
};

class FreshCrescendo {
  constructor(options = {}) {
    this.config = absolutize({ ...(options.config || {}) });
    this.label = options.label;
    this.scoringProvider = null;
  }

  id() {
    return 'promptfoo:redteam:crescendo';
  }

  async callApi(prompt, context, callOptions) {
    const inner = await loadApiProvider('promptfoo:redteam:crescendo', {
      options: { config: { ...this.config } },
      basePath: __dirname,
    });
    if (!this.scoringProvider) {
      this.scoringProvider = await loadApiProvider(SCORING_PROVIDER.id, {
        options: { config: SCORING_PROVIDER.config },
        basePath: __dirname,
      });
    }
    inner.scoringProvider = this.scoringProvider;
    const response = await inner.callApi(prompt, context, callOptions);
    const vars = (context && context.vars) || {};
    response.metadata = {
      ...(response.metadata || {}),
      redteam_conversation: {
        eval_id: (context && context.evaluationId) || vars.__evalId,
        attack_id: vars.attack_id,
        repeat_index: (context && context.repeatIndex) ?? vars.__repeatIndex,
      },
    };
    return response;
  }
}

module.exports = FreshCrescendo;
