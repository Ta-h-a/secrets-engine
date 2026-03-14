import { app, BrowserWindow, ipcMain } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as childProcess from 'child_process';
import log from 'electron-log';
import {
  Finding,
  CommitDecision,
  ScriptExecutionResult,
  SecretExtractionResult,
  AwsCredentials,
  AwsCredentialCheckResult,
  AwsCredentialSaveResult,
  generateAwsReplacement,
  detectLanguage,
} from '../shared/types';

log.initialize();
log.info('SecretLens Desktop starting...');

let mainWindow: BrowserWindow | null = null;
let pendingFindings: Finding[] = [];
let outputFile: string = '';
let repoPath: string = '';  // set from --repo-path CLI arg

// ─── AWS credential state (in-memory for the session) ────────────────────────
// We keep the active credentials here so every script execution inherits them
// without having to re-read from disk.
let sessionAwsCredentials: AwsCredentials | null = null;

// ─── Window ──────────────────────────────────────────────────────────────────

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 960,
    height: 760,
    resizable: true,
    minimizable: true,
    maximizable: true,
    title: 'SecretLens',
    backgroundColor: '#ffffff',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  const isDev = !app.isPackaged;

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173').catch(() => {
      const rendererPath = path.join(__dirname, '../../renderer/index.html');
      log.info('Dev server not running, loading renderer from:', rendererPath);
      if (mainWindow) mainWindow.loadFile(rendererPath);
    });
  } else {
    const rendererPath = path.join(__dirname, '../../renderer/index.html');
    log.info('Loading renderer from:', rendererPath);
    mainWindow.loadFile(rendererPath);
  }

  mainWindow.webContents.on('did-fail-load', (_event, errorCode, errorDescription) => {
    log.error('Failed to load:', errorCode, errorDescription);
  });

  mainWindow.on('closed', () => { mainWindow = null; });
  log.info('Main window created');
}

app.whenReady().then(() => {
  createWindow();
  setupIPC();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ─── IPC Handlers ────────────────────────────────────────────────────────────

function setupIPC(): void {

  // ── Findings ──────────────────────────────────────────────────────────────

  ipcMain.handle('get-findings', async () => {
    log.info('IPC: get-findings → returning', pendingFindings.length, 'findings');
    return pendingFindings;
  });

  // ── Repo name ─────────────────────────────────────────────────────────────
  // Derived from `git rev-parse --show-toplevel` so we get the real repo dir,
  // not the Electron renderer path (which was the previous broken behaviour).

  ipcMain.handle('get-repo-name', async (): Promise<string> => {
    // Prefer the path passed explicitly by the hook via --repo-path
    const gitRoot = repoPath || process.cwd();
    try {
      const result = childProcess.spawnSync('git', ['rev-parse', '--show-toplevel'], {
        encoding: 'utf8',
        cwd: gitRoot,
      });
      if (result.status === 0 && result.stdout) {
        const repoName = path.basename(result.stdout.trim());
        log.info('IPC: get-repo-name →', repoName);
        return repoName;
      }
    } catch (e) {
      log.warn('IPC: get-repo-name git failed:', e);
    }
    return 'unknown-repo';
  });

  // ── Commit decision ───────────────────────────────────────────────────────

  ipcMain.handle('resolve-commit', async (_event, data: CommitDecision) => {
    log.info(
      `IPC: resolve-commit allowed=${data.allowed.length} blocked=${data.blocked.length} ` +
      `resolved=${data.resolved_count} skipped=${data.skipped_count}`,
    );
    if (outputFile) {
      try {
        fs.writeFileSync(outputFile, JSON.stringify(data, null, 2), 'utf8');
        log.info('Wrote commit decision to:', outputFile);
      } catch (e) {
        log.error('Failed to write output file:', e);
      }
    }
    return { success: true };
  });

  // ── AWS credential check ──────────────────────────────────────────────────
  // Called once at startup (and on demand) to tell the UI whether credentials
  // are already present and valid.

  ipcMain.handle('check-aws-credentials', async (): Promise<AwsCredentialCheckResult> => {
    log.info('IPC: check-aws-credentials');

    // 1. Already confirmed this session → fast path
    if (sessionAwsCredentials) {
      const identity = await stsGetCallerIdentity(sessionAwsCredentials);
      if (identity) {
        return { valid: true, identity, source: 'secretlens-profile' };
      }
      // Session credentials went bad (unlikely, but reset)
      sessionAwsCredentials = null;
    }

    // 2. Check environment variables
    const envKey = process.env.AWS_ACCESS_KEY_ID;
    const envSecret = process.env.AWS_SECRET_ACCESS_KEY;
    if (envKey && envSecret) {
      const creds: AwsCredentials = {
        accessKeyId: envKey,
        secretAccessKey: envSecret,
        region: process.env.AWS_DEFAULT_REGION ?? process.env.AWS_REGION ?? 'us-east-1',
      };
      const identity = await stsGetCallerIdentity(creds);
      if (identity) {
        sessionAwsCredentials = creds;
        return { valid: true, identity, source: 'env' };
      }
    }

    // 3. Check ~/.aws/credentials for a [secretlens] profile
    const secretlensProfile = readAwsProfile('secretlens');
    if (secretlensProfile) {
      const identity = await stsGetCallerIdentity(secretlensProfile);
      if (identity) {
        sessionAwsCredentials = secretlensProfile;
        return { valid: true, identity, source: 'secretlens-profile' };
      }
      return {
        valid: false,
        source: 'secretlens-profile',
        error: 'SecretLens AWS profile found but credentials are invalid or expired.',
      };
    }

    // 4. Check ~/.aws/credentials [default] profile
    const defaultProfile = readAwsProfile('default');
    if (defaultProfile) {
      const identity = await stsGetCallerIdentity(defaultProfile);
      if (identity) {
        sessionAwsCredentials = defaultProfile;
        return { valid: true, identity, source: 'aws-file' };
      }
    }

    return {
      valid: false,
      error: 'No AWS credentials found. Please enter your AWS Access Key to continue.',
    };
  });

  // ── Save AWS credentials ──────────────────────────────────────────────────
  // Writes credentials to ~/.aws/credentials under [secretlens] and verifies
  // them with STS before confirming.

  ipcMain.handle(
    'save-aws-credentials',
    async (_event, creds: AwsCredentials): Promise<AwsCredentialSaveResult> => {
      log.info('IPC: save-aws-credentials key=', creds.accessKeyId.slice(0, 8) + '…');

      // Verify first — never store credentials we know are wrong
      const identity = await stsGetCallerIdentity(creds);
      if (!identity) {
        return {
          success: false,
          error: 'Credentials could not be verified with AWS STS. ' +
            'Please check your Access Key ID, Secret Access Key, and region.',
        };
      }

      // Write to ~/.aws/credentials
      try {
        writeAwsProfile('secretlens', creds);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        log.error('Failed to write AWS credentials file:', msg);
        return { success: false, error: `Could not save credentials: ${msg}` };
      }

      // Store in session memory
      sessionAwsCredentials = creds;
      log.info('AWS credentials saved and verified. Identity:', identity);

      return { success: true, identity };
    },
  );

  // ── Extract raw secret from source file ───────────────────────────────────

  ipcMain.handle(
    'extract-secret',
    async (
      _event,
      { filePath, lineNumber }: { filePath: string; lineNumber: number },
    ): Promise<SecretExtractionResult> => {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        const line = lines[lineNumber - 1];
        if (line === undefined) {
          return { success: false, secret_value: '', error: `Line ${lineNumber} not found in ${filePath}` };
        }

        const secretValue = extractSecretFromLine(line);
        if (!secretValue) {
          return {
            success: false,
            secret_value: '',
            error: `Could not extract secret value from line ${lineNumber}: ${line.trim()}`,
          };
        }

        log.info(`Extracted secret from ${filePath}:${lineNumber} (${secretValue.length} chars)`);
        return { success: true, secret_value: secretValue };
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return { success: false, secret_value: '', error: msg };
      }
    },
  );

  // ── Execute script with AWS credentials injected ──────────────────────────
  // This is the critical piece: regardless of what is in the user's shell
  // environment, we inject the stored credentials into the child process env.
  // The save script (Python/shell) then picks them up via the standard
  // AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars.

  ipcMain.handle(
    'execute-script',
    async (
      _event,
      { script, language }: { script: string; language: string },
    ): Promise<ScriptExecutionResult> => {
      log.info('IPC: execute-script language=', language);

      if (!sessionAwsCredentials) {
        return {
          success: false,
          output: '',
          error: 'No AWS credentials available. Please set up your AWS credentials first.',
        };
      }

      const ext = language === 'python' ? '.py' : '.sh';
      const tmpScript = path.join(app.getPath('temp'), `secretlens_script_${Date.now()}${ext}`);

      try {
        // The SecretLens API returns code with every line commented out (`# `).
        // Strip those markers so the script is actually executable.
        const executableScript = uncommentScript(script);
        fs.writeFileSync(tmpScript, executableScript, 'utf8');
        if (ext === '.sh') fs.chmodSync(tmpScript, 0o755);

        const cmd = ext === '.py' ? `python3 "${tmpScript}"` : `bash "${tmpScript}"`;

        // Build child process environment: inherit current env, then overlay
        // credentials so they are always available to the script.
        const childEnv: NodeJS.ProcessEnv = {
          ...process.env,
          AWS_ACCESS_KEY_ID: sessionAwsCredentials.accessKeyId,
          AWS_SECRET_ACCESS_KEY: sessionAwsCredentials.secretAccessKey,
          AWS_DEFAULT_REGION: sessionAwsCredentials.region,
          AWS_REGION: sessionAwsCredentials.region,
          // Clear any profile that might override the explicit key/secret
          AWS_PROFILE: undefined,
          AWS_CONFIG_FILE: undefined,
        };

        const result = await runCommandWithEnv(cmd, childEnv);

        log.info('Script exit code:', result.exitCode);
        log.info('Script stdout:', result.stdout || '(empty)');
        if (result.stderr) log.warn('Script stderr:', result.stderr);

        fs.existsSync(tmpScript) && fs.unlinkSync(tmpScript);

        // Extract AWS key name from script output using several heuristics
        const awsKeyName = extractAwsKeyNameFromOutput(result.stdout, executableScript);
        log.info('Extracted AWS key name:', awsKeyName ?? '(none)');

        return {
          success: result.exitCode === 0,
          output: result.stdout + (result.stderr ? `\nSTDERR: ${result.stderr}` : ''),
          error: result.exitCode !== 0
            ? (result.stderr || 'Script exited with non-zero code')
            : undefined,
          aws_key_name: awsKeyName,
        };
      } catch (e) {
        fs.existsSync(tmpScript) && fs.unlinkSync(tmpScript);
        const msg = e instanceof Error ? e.message : String(e);
        return { success: false, output: '', error: msg };
      }
    },
  );

  // ── Replace raw secret in source file with AWS SDK reference ─────────────

  ipcMain.handle(
    'replace-secret',
    async (
      _event,
      {
        filePath,
        lineNumber,
        secretValue,
        awsKeyName,
      }: { filePath: string; lineNumber: number; secretValue: string; awsKeyName: string },
    ): Promise<{ success: boolean; error?: string }> => {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const language = detectLanguage(filePath);
        const replacement = generateAwsReplacement(language, awsKeyName);

        const lines = content.split('\n');
        const targetLine = lines[lineNumber - 1];
        if (targetLine === undefined) {
          return { success: false, error: `Line ${lineNumber} not found in ${filePath}` };
        }

        const escapedSecret = secretValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(`(['"\`]?)${escapedSecret}\\1`);

        if (!regex.test(targetLine)) {
          lines[lineNumber - 1] = replaceValuePortion(targetLine, replacement, language);
        } else {
          lines[lineNumber - 1] = targetLine.replace(regex, replacement);
        }

        fs.writeFileSync(filePath, lines.join('\n'), 'utf8');
        log.info(`Replaced secret in ${filePath}:${lineNumber} with ${replacement}`);
        return { success: true };
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return { success: false, error: msg };
      }
    },
  );

  ipcMain.handle('get-settings', async () => ({
    aiProvider: 'none',
    theme: 'light',
    autoBlock: true,
  }));
}

// ─── AWS credential helpers ───────────────────────────────────────────────────

/**
 * Call sts:GetCallerIdentity to verify credentials.
 * Returns the ARN string on success, null on failure.
 * Uses Python boto3 if available, falls back to AWS CLI.
 */
async function stsGetCallerIdentity(creds: AwsCredentials): Promise<string | null> {
  // Try Python boto3 first (most reliable, no CLI dependency)
  const pythonScript = `
import json, sys
try:
    import boto3
    client = boto3.client(
        'sts',
        aws_access_key_id='${escapeSingleQuote(creds.accessKeyId)}',
        aws_secret_access_key='${escapeSingleQuote(creds.secretAccessKey)}',
        region_name='${escapeSingleQuote(creds.region)}',
    )
    r = client.get_caller_identity()
    print(r.get('Arn', 'ok'))
    sys.exit(0)
except Exception as e:
    print(str(e), file=sys.stderr)
    sys.exit(1)
`;

  const tmpPy = path.join(os.tmpdir(), `sl_sts_check_${Date.now()}.py`);
  try {
    fs.writeFileSync(tmpPy, pythonScript, 'utf8');
    const pyResult = await runCommandWithEnv(`python3 "${tmpPy}"`, {
      ...process.env,
      AWS_ACCESS_KEY_ID: creds.accessKeyId,
      AWS_SECRET_ACCESS_KEY: creds.secretAccessKey,
      AWS_DEFAULT_REGION: creds.region,
    });
    fs.existsSync(tmpPy) && fs.unlinkSync(tmpPy);

    if (pyResult.exitCode === 0 && pyResult.stdout.trim()) {
      return pyResult.stdout.trim();
    }
  } catch {
    fs.existsSync(tmpPy) && fs.unlinkSync(tmpPy);
  }

  // Fallback: AWS CLI
  const cliResult = await runCommandWithEnv('aws sts get-caller-identity --output text --query Arn', {
    ...process.env,
    AWS_ACCESS_KEY_ID: creds.accessKeyId,
    AWS_SECRET_ACCESS_KEY: creds.secretAccessKey,
    AWS_DEFAULT_REGION: creds.region,
  });

  if (cliResult.exitCode === 0 && cliResult.stdout.trim()) {
    return cliResult.stdout.trim();
  }

  return null;
}

/**
 * Read a named profile from ~/.aws/credentials.
 * Returns null if the profile doesn't exist or is incomplete.
 */
function readAwsProfile(profileName: string): AwsCredentials | null {
  const credFile = path.join(os.homedir(), '.aws', 'credentials');
  if (!fs.existsSync(credFile)) return null;

  try {
    const text = fs.readFileSync(credFile, 'utf8');
    const profileHeader = new RegExp(`\\[${profileName}\\]`, 'i');
    const sections = text.split(/^\[/m);

    for (const section of sections) {
      if (!profileHeader.test(`[${section}`)) continue;

      const lines = section.split('\n');
      let keyId = '';
      let secret = '';
      let region = 'us-east-1';

      for (const line of lines) {
        const m = line.match(/^\s*([\w_]+)\s*=\s*(.+)$/);
        if (!m) continue;
        const k = m[1].trim().toLowerCase();
        const v = m[2].trim();
        if (k === 'aws_access_key_id') keyId = v;
        if (k === 'aws_secret_access_key') secret = v;
        if (k === 'region' || k === 'aws_default_region') region = v;
      }

      if (keyId && secret) return { accessKeyId: keyId, secretAccessKey: secret, region };
    }
  } catch {
    // ignore read errors
  }

  return null;
}

/**
 * Write (upsert) a named profile into ~/.aws/credentials.
 * Creates the file and directory if they don't exist.
 * Leaves all other profiles untouched.
 */
function writeAwsProfile(profileName: string, creds: AwsCredentials): void {
  const awsDir = path.join(os.homedir(), '.aws');
  const credFile = path.join(awsDir, 'credentials');

  if (!fs.existsSync(awsDir)) {
    fs.mkdirSync(awsDir, { recursive: true, mode: 0o700 });
  }

  let existing = '';
  if (fs.existsSync(credFile)) {
    existing = fs.readFileSync(credFile, 'utf8');
  }

  const profileHeader = `[${profileName}]`;
  const newBlock = [
    profileHeader,
    `aws_access_key_id = ${creds.accessKeyId}`,
    `aws_secret_access_key = ${creds.secretAccessKey}`,
    `region = ${creds.region}`,
    '',
  ].join('\n');

  if (existing.includes(profileHeader)) {
    // Replace the existing block
    const replaced = existing.replace(
      new RegExp(`\\[${profileName}\\][^\\[]*`, 's'),
      newBlock,
    );
    fs.writeFileSync(credFile, replaced, { encoding: 'utf8', mode: 0o600 });
  } else {
    // Append
    const separator = existing.endsWith('\n') || existing === '' ? '' : '\n';
    fs.writeFileSync(credFile, existing + separator + newBlock, {
      encoding: 'utf8',
      mode: 0o600,
    });
  }
}

// ─── Process helpers ──────────────────────────────────────────────────────────

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

function runCommandWithEnv(cmd: string, env: NodeJS.ProcessEnv, timeout = 60_000): Promise<CommandResult> {
  return new Promise((resolve) => {
    const proc = childProcess.exec(cmd, { timeout, env }, (error, stdout, stderr) => {
      resolve({
        stdout: stdout || '',
        stderr: stderr || '',
        exitCode: error?.code ?? 0,
      });
    });
    proc.on('error', (err) => {
      resolve({ stdout: '', stderr: err.message, exitCode: 1 });
    });
  });
}

// ─── Secret extraction / replacement helpers ──────────────────────────────────

/**
 * Extract the secret value from a source line.
 * Handles patterns like:
 *   API_KEY = "sk-proj-abc123"
 *   api_key: 'sk-proj-abc123'
 *   API_KEY=sk-proj-abc123
 */
/**
 * The SecretLens API returns save scripts with every code line prefixed by `# `.
 * This strips those comment markers so the script is actually executable.
 *
 * Rules:
 *  - Lines that are exactly `#` or `# ` (no content) → empty line
 *  - Lines starting with `# ` where the content after `# ` begins with a
 *    code-like character (letter, digit, whitespace for indent) → uncommented
 *  - Separator/header lines (content is `===`, `---`, all-caps description,
 *    `Secret N:`, etc.) → kept as-is (remain Python comments)
 */
function uncommentScript(script: string): string {
  // After stripping `# `, content that starts with these patterns is code
  const CODE_START = /^(\s|import |from |def |class |if |else|elif |try:|except|finally:|return |raise |with |for |while |async |await |const |let |var |function |module\.|require\(|client|secret|response|boto|json|sys|print\(|exit\(|#)/;

  return script
    .split('\n')
    .map((line) => {
      if (!line.startsWith('#')) return line;

      // `#` alone or `# ` with no content → blank line
      const content = line.startsWith('# ') ? line.slice(2) : line.slice(1);
      if (!content.trim()) return '';

      // Separator/header lines — keep as Python comment
      if (/^[=\-]{3,}/.test(content)) return line;

      // Code line — strip the comment marker
      if (CODE_START.test(content)) return content;

      // Default: keep as comment (metadata, plain-english descriptions, etc.)
      return line;
    })
    .join('\n');
}

function extractSecretFromLine(line: string): string {
  // Match quoted value after = or :
  const quotedMatch = line.match(/(?:=|:)\s*["'`]([^"'`\n]+)["'`]/);
  if (quotedMatch) return quotedMatch[1];

  // Match unquoted value after =
  const unquotedMatch = line.match(/=\s*([^\s#\n]+)/);
  if (unquotedMatch) return unquotedMatch[1];

  return '';
}

/**
 * Replace the value portion of a line when exact string substitution fails.
 */
function replaceValuePortion(line: string, replacement: string, language: string): string {
  if (/=\s*["'`]/.test(line)) {
    return line.replace(/=\s*["'`][^"'`]*["'`]/, `= ${replacement}`);
  }
  if (/:\s*["']/.test(line)) {
    return line.replace(/:\s*["'][^"']*["']/, `: ${replacement}`);
  }
  if (/=/.test(line)) {
    return line.replace(/=\s*[^\s#\n]+/, `= ${replacement}`);
  }
  return line;
}

/**
 * Try to extract the AWS Secrets Manager key name from a script's stdout.
 * The SecretLens API save scripts typically print something like:
 *   "Secret stored: MY_SECRET_KEY"  or  "Secret ARN: arn:aws:…/MY_KEY"
 * We also fall back to scanning the script source for the secret name.
 */
function extractAwsKeyNameFromOutput(output: string, scriptSource: string): string | undefined {
  // Pattern 1: ARN in output — most reliable, extract the name portion.
  // AWS appends a 6-char random suffix to the ARN (e.g. "dev-ZPA2KC") that is
  // NOT part of the logical secret name, so we strip it.
  const arnMatch = output.match(/arn:aws:secretsmanager:[^:]+:\d+:secret:([A-Za-z0-9_\-/]+)/i);
  if (arnMatch?.[1]) {
    return arnMatch[1].replace(/-[A-Za-z0-9]{6}$/, '');
  }

  // Pattern 2: explicit "secret stored/created/updated: NAME" in output
  const outputMatch = output.match(
    /(?:secret[_\s]*(?:stored|created|updated|name|id))[:\s="']+([A-Za-z0-9_\-/]+)/i,
  );
  if (outputMatch?.[1]) return outputMatch[1];

  // Pattern 3: Scan script source for the exact `secret_name` variable (Python)
  // Must be `secret_name` — NOT `region_name`, `client_name`, etc.
  const pyMatch = scriptSource.match(/\bsecret_name\s*=\s*["']([^"'\n]+)["']/i);
  if (pyMatch?.[1]) return pyMatch[1];

  // Pattern 4: JS `secretName` variable
  const jsMatch = scriptSource.match(/\bsecretName\s*=\s*["']([^"'\n]+)["']/i);
  if (jsMatch?.[1]) return jsMatch[1];

  return undefined;
}

function escapeSingleQuote(s: string): string {
  return s.replace(/'/g, "\\'");
}

// ─── CLI Argument Parsing ─────────────────────────────────────────────────────

process.argv.forEach((arg, index) => {
  if (arg === '--findings-file' && index + 1 < process.argv.length) {
    const findingsFile = process.argv[index + 1];
    try {
      const raw = fs.readFileSync(findingsFile, 'utf8');
      const data = JSON.parse(raw);
      pendingFindings = (data.blocking_findings ?? data.findings ?? []) as Finding[];
      log.info(`Loaded ${pendingFindings.length} findings from: ${findingsFile}`);
    } catch (e) {
      log.error('Failed to load findings file:', e);
      pendingFindings = [];
    }
  }

  if (arg === '--findings' && index + 1 < process.argv.length) {
    try {
      const data = JSON.parse(process.argv[index + 1]);
      pendingFindings = (data.blocking_findings ?? data.findings ?? []) as Finding[];
      log.info(`Loaded ${pendingFindings.length} findings from --findings arg`);
    } catch (e) {
      log.error('Failed to parse --findings arg:', e);
    }
  }

  if (arg === '--output-file' && index + 1 < process.argv.length) {
    outputFile = process.argv[index + 1];
    log.info('Output file:', outputFile);
  }

  if (arg === '--repo-path' && index + 1 < process.argv.length) {
    repoPath = process.argv[index + 1];
    log.info('Repo path:', repoPath);
  }
});
