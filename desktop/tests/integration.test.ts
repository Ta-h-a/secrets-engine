import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';

const ENGINE_PATH = '/home/keys/.secretlens/bin/secretlens';
const TEST_REPO = '/home/keys/Documents/work/hackathon/test-repo';

describe('End-to-End Integration Tests', () => {
  describe('Git Hook Flow', () => {
    it('should have hook installed in test-repo', () => {
      const hookPath = path.join(TEST_REPO, '.git', 'hooks', 'pre-commit');
      expect(fs.existsSync(hookPath)).toBe(true);
    });

    it('should have executable hook', () => {
      const hookPath = path.join(TEST_REPO, '.git', 'hooks', 'pre-commit');
      const stats = fs.statSync(hookPath);
      expect((stats.mode & 0o111)).not.toBe(0);
    });

    it('should have engine binary available', () => {
      expect(fs.existsSync(ENGINE_PATH)).toBe(true);
    });

    it('should engine be executable', () => {
      const stats = fs.statSync(ENGINE_PATH);
      expect((stats.mode & 0o111)).not.toBe(0);
    });
  });

  describe('Direct Engine Tests', () => {
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

        engine.stdout.on('data', (data) => { stdout += data.toString(); });
        engine.stderr.on('data', (data) => { stderr += data.toString(); });

        engine.on('close', (code) => {
          resolve(stdout.trim());
        });

        engine.stdin.write(payload);
        engine.stdin.end();
      });
    };

    it('should detect AWS key', async () => {
      const result = await runEngine([
        { filePath: 'test.py', content: 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"' }
      ]);
      const response = JSON.parse(result);
      expect(response.payload.findings.length).toBeGreaterThan(0);
    });

    it('should not flag clean code', async () => {
      const result = await runEngine([
        { filePath: 'test.py', content: 'print("hello world")' }
      ]);
      const response = JSON.parse(result);
      expect(response.payload.findings.length).toBe(0);
    });
  });
});
