import { describe, it, expect } from 'vitest';

interface Finding {
  id: string;
  filePath: string;
  lineNumber: number;
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  message: string;
  description: string;
  recommendations: string[];
}

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

const sortFindingsBySeverity = (findings: Finding[]): Finding[] => {
  return [...findings].sort((a, b) => 
    (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0)
  );
};

const filterBlockingFindings = (findings: Finding[]): Finding[] => {
  return findings.filter(f => 
    f.severity === 'critical' || f.severity === 'high'
  );
};

const groupByFile = (findings: Finding[]): Record<string, Finding[]> => {
  return findings.reduce((acc, finding) => {
    const file = finding.filePath;
    if (!acc[file]) acc[file] = [];
    acc[file].push(finding);
    return acc;
  }, {} as Record<string, Finding[]>);
};

const getFindingStats = (findings: Finding[]) => {
  return {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    files: new Set(findings.map(f => f.filePath)).size
  };
};

describe('Finding Utilities', () => {
  const mockFindings: Finding[] = [
    {
      id: '1',
      filePath: 'config.py',
      lineNumber: 1,
      ruleId: 'SEC-001',
      severity: 'high',
      title: 'AWS Key',
      message: 'AWS key found',
      description: 'desc',
      recommendations: ['Fix it']
    },
    {
      id: '2',
      filePath: '.env',
      lineNumber: 2,
      ruleId: 'SEC-005',
      severity: 'critical',
      title: 'Stripe Key',
      message: 'Stripe key found',
      description: 'desc',
      recommendations: ['Fix it']
    },
    {
      id: '3',
      filePath: 'auth.py',
      lineNumber: 10,
      ruleId: 'SEC-004',
      severity: 'low',
      title: 'Password',
      message: 'Password found',
      description: 'desc',
      recommendations: ['Fix it']
    }
  ];

  describe('sortFindingsBySeverity', () => {
    it('should sort findings by severity (critical first)', () => {
      const sorted = sortFindingsBySeverity(mockFindings);
      expect(sorted[0].severity).toBe('critical');
      expect(sorted[1].severity).toBe('high');
      expect(sorted[2].severity).toBe('low');
    });

    it('should not mutate original array', () => {
      const original = [...mockFindings];
      sortFindingsBySeverity(mockFindings);
      expect(mockFindings).toEqual(original);
    });
  });

  describe('filterBlockingFindings', () => {
    it('should filter only critical and high severity', () => {
      const blocking = filterBlockingFindings(mockFindings);
      expect(blocking.length).toBe(2);
      expect(blocking.every(f => f.severity === 'critical' || f.severity === 'high')).toBe(true);
    });
  });

  describe('groupByFile', () => {
    it('should group findings by file path', () => {
      const grouped = groupByFile(mockFindings);
      expect(Object.keys(grouped)).toHaveLength(3);
      expect(grouped['config.py']).toHaveLength(1);
      expect(grouped['.env']).toHaveLength(1);
      expect(grouped['auth.py']).toHaveLength(1);
    });
  });

  describe('getFindingStats', () => {
    it('should calculate correct statistics', () => {
      const stats = getFindingStats(mockFindings);
      expect(stats.total).toBe(3);
      expect(stats.critical).toBe(1);
      expect(stats.high).toBe(1);
      expect(stats.medium).toBe(0);
      expect(stats.low).toBe(1);
      expect(stats.files).toBe(3);
    });
  });
});

describe('SEVERITY_COLORS', () => {
  const SEVERITY_COLORS: Record<string, string> = {
    critical: '#ec1313',
    high: '#ff8a00',
    medium: '#ffd600',
    low: '#007aff'
  };

  it('should have colors for all severities', () => {
    expect(SEVERITY_COLORS.critical).toBe('#ec1313');
    expect(SEVERITY_COLORS.high).toBe('#ff8a00');
    expect(SEVERITY_COLORS.medium).toBe('#ffd600');
    expect(SEVERITY_COLORS.low).toBe('#007aff');
  });
});

describe('SEVERITY_LABELS', () => {
  const SEVERITY_LABELS: Record<string, string> = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'MEDIUM',
    low: 'LOW'
  };

  it('should have uppercase labels', () => {
    Object.values(SEVERITY_LABELS).forEach(label => {
      expect(label).toBe(label.toUpperCase());
    });
  });
});
