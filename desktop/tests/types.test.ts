import { describe, it, expect } from 'vitest';
import { detectLanguage, generateAwsReplacement } from '../src/shared/types';

describe('detectLanguage', () => {
  it('should detect python from .py extension', () => {
    expect(detectLanguage('src/config.py')).toBe('python');
  });
  it('should detect javascript from .js extension', () => {
    expect(detectLanguage('src/config.js')).toBe('javascript');
  });
  it('should detect typescript from .ts extension', () => {
    expect(detectLanguage('src/config.ts')).toBe('typescript');
  });
  it('should detect shell from .env extension', () => {
    expect(detectLanguage('.env')).toBe('shell');
  });
  it('should detect yaml from .yaml extension', () => {
    expect(detectLanguage('config.yaml')).toBe('yaml');
  });
  it('should return shell as default for unknown extensions', () => {
    expect(detectLanguage('Makefile')).toBe('shell');
  });
});

describe('generateAwsReplacement', () => {
  it('should generate python os.environ.get for python', () => {
    const result = generateAwsReplacement('python', 'my-secret-key');
    expect(result).toBe("os.environ.get('MY_SECRET_KEY')");
  });
  it('should generate process.env for javascript', () => {
    const result = generateAwsReplacement('javascript', 'my-secret-key');
    expect(result).toBe('process.env.MY_SECRET_KEY');
  });
  it('should generate process.env for typescript', () => {
    const result = generateAwsReplacement('typescript', 'API_TOKEN');
    expect(result).toBe('process.env.API_TOKEN');
  });
  it('should generate ENV[] for ruby', () => {
    const result = generateAwsReplacement('ruby', 'api-key');
    expect(result).toBe("ENV['API_KEY']");
  });
  it('should generate os.Getenv for go', () => {
    const result = generateAwsReplacement('go', 'secret_name');
    expect(result).toBe('os.Getenv("SECRET_NAME")');
  });
  it('should replace dashes with underscores and uppercase', () => {
    const result = generateAwsReplacement('python', 'stripe-api-key-live');
    expect(result).toBe("os.environ.get('STRIPE_API_KEY_LIVE')");
  });
});
