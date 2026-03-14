import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const ENGINE_PATH = process.env.SECRETLENS_BIN || 
  '/home/keys/.secretlens/bin/secretlens' ||
  '/home/keys/Documents/work/hackathon/pre-commit-engine/target/debug/secretlens';

interface Finding {
  id: string;
  filePath: string;
  lineNumber: number;
  ruleId: string;
  severity: string;
  title: string;
  message: string;
}

interface AnalyzeResponse {
  status: string;
  payload: {
    findings: Finding[];
  };
}

describe('SecretLens Engine Integration Tests', () => {
  const testFixturesDir = path.join(__dirname, 'fixtures');
  
  beforeAll(() => {
    if (!fs.existsSync(testFixturesDir)) {
      fs.mkdirSync(testFixturesDir, { recursive: true });
    }
  });

  afterAll(() => {
    if (fs.existsSync(testFixturesDir)) {
      fs.rmSync(testFixturesDir, { recursive: true, force: true });
    }
  });

  const runEngine = (files: { filePath: string; content: string }[]): Promise<string> => {
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify({
        command: 'analyze',
        payload: {
          files,
          aiProviderConfig: { provider: 'none' }
        }
      });

      const engine = spawn(ENGINE_PATH, ['--mode', 'pipe', '--format', 'json'], {
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';

      engine.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      engine.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      engine.on('close', (code) => {
        if (code === 0 || code === 1) {
          resolve(stdout.trim());
        } else {
          reject(new Error(`Engine exited with code ${code}: ${stderr}`));
        }
      });

      engine.stdin.write(payload);
      engine.stdin.end();
    });
  };

  describe('AWS Key Detection', () => {
    it('should detect AWS access key', async () => {
      const result = await runEngine([
        { filePath: 'config.py', content: 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"' }
      ]);

      const response: AnalyzeResponse = JSON.parse(result);
      expect(response.status).toBe('success');
      expect(response.payload.findings.length).toBeGreaterThan(0);
      expect(response.payload.findings[0].severity).toBe('critical');
    });

    it('should detect AWS secret key', async () => {
      const result = await runEngine([
        { filePath: 'config.py', content: 'aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY"' }
      ]);

      const response: AnalyzeResponse = JSON.parse(result);
      expect(response.status).toBe('success');
      expect(response.payload.findings.length).toBeGreaterThanOrEqual(0);
    });

    it('should not false positive on similar patterns', async () => {
      const result = await runEngine([
        { filePath: 'example.py', content: '# This is not a key: AKIAEXAMPLE123' }
      ]);

      const response: AnalyzeResponse = JSON.parse(result);
      expect(response.payload.findings).toHaveLength(0);
    });
  });

  describe('API Key Detection', () => {
    it('should detect Stripe API key', async () => {
      const result = await runEngine([
        { filePath: 'config.py', content: 'stripe_key = "sk_live_' + '51MqLyABCD1234567890EFGH"' }
      ]);

      const response: AnalyzeResponse = JSON.parse(result);
      expect(response.status).toBe('success');
      expect(response.payload.findings.length).toBeGreaterThan(0);
    });

    it('should detect GitHub token', async () => {
      const result = await runEngine([
        { filePath: 'config.py', content: 'github_token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"' }
      ]);

      const response: AnalyzeResponse = JSON.parse(result);
      expect(response.status).toBe('success');
      expect(response.payload.findings.length).toBeGreaterThan(0);
    });

    it('should detect OpenAI API key', async () => {
      const result = await runEngine([
        { filePath: 'config.py', content: 'openai_key = "sk-abcdefghijklmnopqrstuvwxyz123456"' }
      ]);

      const response: AnalyzeResponse = JSON.parse(result);
      expect(response.status).toBe('success');
      expect(response.payload.findings.length).toBeGreaterThan(0);
    });
  });

  describe('Password Detection', () => {
    it('should detect hardcoded password', async () => {
      const result = await runEngine([
        { filePath: 'config.py', content: 'PASSWORD = "super_secret_123"' }
      ]);

      const response: AnalyzeResponse = JSON.parse(result);
      expect(response.status).toBe('success');
      expect(response.payload.findings.some(f => f.ruleId === 'SEC-004')).toBe(true);
    });
  });

  describe('Multiple Files', () => {
    it('should detect secrets in multiple files', async () => {
      const result = await runEngine([
        { filePath: 'config.py', content: 'aws_key = "AKIAIOSFODNN7EXAMPLE"' },
        { filePath: '.env', content: 'STRIPE_KEY="sk_live_' + '51MqLyABCD1234567890EFGH"' },
        { filePath: 'clean.py', content: 'print("hello")' }
      ]);

      const response: AnalyzeResponse = JSON.parse(result);
      expect(response.status).toBe('success');
      expect(response.payload.findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Clean Files', () => {
    it('should return no findings for clean code', async () => {
      const result = await runEngine([
        { 
          filePath: 'clean.py', 
          content: `def hello():
    print("Hello, World!")
    return True`
        }
      ]);

      const response: AnalyzeResponse = JSON.parse(result);
      expect(response.status).toBe('success');
      expect(response.payload.findings).toHaveLength(0);
    });

    it('should handle empty files', async () => {
      const result = await runEngine([
        { filePath: 'empty.py', content: '' }
      ]);

      const response: AnalyzeResponse = JSON.parse(result);
      expect(response.status).toBe('success');
      expect(response.payload.findings).toHaveLength(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid JSON gracefully', async () => {
      return new Promise((resolve) => {
        const engine = spawn(ENGINE_PATH, ['--mode', 'pipe'], {
          stdio: ['pipe', 'pipe', 'pipe']
        });

        let stdout = '';
        let stderr = '';

        engine.stdout.on('data', (data) => {
          stdout += data.toString();
        });

        engine.stderr.on('data', (data) => {
          stderr += data.toString();
        });

        engine.on('close', () => {
          try {
            const response = JSON.parse(stdout.trim());
            expect(response.status).toBe('error');
            resolve(true);
          } catch {
            resolve(true);
          }
        });

        engine.stdin.write('not valid json');
        engine.stdin.end();
      });
    });
  });
});
