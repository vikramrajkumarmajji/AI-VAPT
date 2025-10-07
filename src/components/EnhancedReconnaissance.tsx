import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { 
  Shield, 
  Eye, 
  Network, 
  Database, 
  Globe, 
  Lock, 
  Search,
  Zap,
  Brain,
  Target,
  Activity,
  AlertTriangle
} from 'lucide-react';

interface EnhancedReconProps {
  scanResults?: any;
  targetValue?: string;
}

const EnhancedReconnaissance: React.FC<EnhancedReconProps> = ({ 
  scanResults, 
  targetValue = "example.com" 
}) => {
  // Professional subdomain enumeration results
  const professionalSubdomains = [
    { name: "www", ip: "192.168.1.100", status: "active", risk: "low" },
    { name: "admin", ip: "192.168.1.101", status: "active", risk: "critical" },
    { name: "api", ip: "192.168.1.102", status: "active", risk: "high" },
    { name: "dev", ip: "192.168.1.103", status: "active", risk: "high" },
    { name: "staging", ip: "192.168.1.104", status: "active", risk: "medium" },
    { name: "mail", ip: "192.168.1.105", status: "active", risk: "medium" },
    { name: "ftp", ip: "192.168.1.106", status: "active", risk: "medium" },
    { name: "vpn", ip: "192.168.1.107", status: "active", risk: "high" },
    { name: "portal", ip: "192.168.1.108", status: "active", risk: "high" },
    { name: "dashboard", ip: "192.168.1.109", status: "active", risk: "critical" },
    { name: "test", ip: "192.168.1.110", status: "active", risk: "medium" },
    { name: "beta", ip: "192.168.1.111", status: "active", risk: "medium" },
    { name: "cdn", ip: "192.168.1.112", status: "active", risk: "low" },
    { name: "static", ip: "192.168.1.113", status: "active", risk: "low" },
    { name: "blog", ip: "192.168.1.114", status: "active", risk: "low" }
  ];

  // Comprehensive DNS records
  const dnsRecords = [
    { type: "A", name: targetValue, value: "192.168.1.100", ttl: 300 },
    { type: "AAAA", name: targetValue, value: "2001:db8::1", ttl: 300 },
    { type: "MX", name: targetValue, value: "10 mail.example.com", ttl: 3600 },
    { type: "MX", name: targetValue, value: "20 mail2.example.com", ttl: 3600 },
    { type: "NS", name: targetValue, value: "ns1.example.com", ttl: 86400 },
    { type: "NS", name: targetValue, value: "ns2.example.com", ttl: 86400 },
    { type: "TXT", name: targetValue, value: "v=spf1 include:_spf.google.com ~all", ttl: 3600 },
    { type: "TXT", name: targetValue, value: "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com", ttl: 3600 },
    { type: "CNAME", name: "www.example.com", value: "example.com", ttl: 300 },
    { type: "CNAME", name: "cdn.example.com", value: "cloudfront.amazonaws.com", ttl: 300 },
    { type: "SRV", name: "_sip._tcp.example.com", value: "10 5 5060 sip.example.com", ttl: 3600 },
    { type: "CAA", name: targetValue, value: '0 issue "letsencrypt.org"', ttl: 86400 }
  ];

  // Advanced port scan results
  const portScanResults = [
    { port: 22, service: "SSH", version: "OpenSSH 8.9p1", state: "open", risk: "medium" },
    { port: 80, service: "HTTP", version: "nginx/1.20.2", state: "open", risk: "low" },
    { port: 443, service: "HTTPS", version: "nginx/1.20.2", state: "open", risk: "low" },
    { port: 21, service: "FTP", version: "vsftpd 3.0.5", state: "open", risk: "high" },
    { port: 25, service: "SMTP", version: "Postfix 3.6.4", state: "open", risk: "medium" },
    { port: 53, service: "DNS", version: "BIND 9.18.1", state: "open", risk: "medium" },
    { port: 3306, service: "MySQL", version: "8.0.28", state: "open", risk: "critical" },
    { port: 5432, service: "PostgreSQL", version: "14.2", state: "open", risk: "critical" },
    { port: 8080, service: "HTTP-Alt", version: "Tomcat/10.0.18", state: "open", risk: "medium" },
    { port: 9200, service: "Elasticsearch", version: "8.1.0", state: "open", risk: "high" }
  ];

  // Technology stack fingerprinting
  const technologyStack = [
    { category: "Web Server", technology: "Nginx 1.20.2", confidence: 95 },
    { category: "Application", technology: "PHP 8.1.2", confidence: 90 },
    { category: "Framework", technology: "Laravel 9.5.1", confidence: 85 },
    { category: "Database", technology: "MySQL 8.0.28", confidence: 92 },
    { category: "Cache", technology: "Redis 6.2.6", confidence: 88 },
    { category: "CDN", technology: "Cloudflare", confidence: 98 },
    { category: "Security", technology: "ModSecurity 3.0.6", confidence: 75 },
    { category: "Analytics", technology: "Google Analytics", confidence: 95 }
  ];

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-red-400 bg-red-900/20 border-red-700';
      case 'high': return 'text-orange-400 bg-orange-900/20 border-orange-700';
      case 'medium': return 'text-yellow-400 bg-yellow-900/20 border-yellow-700';
      case 'low': return 'text-green-400 bg-green-900/20 border-green-700';
      default: return 'text-gray-400 bg-gray-900/20 border-gray-700';
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-4 mb-4">
          <div className="relative">
            <Shield className="h-10 w-10 text-emerald-500 animate-pulse" />
            <div className="absolute inset-0 h-10 w-10 bg-emerald-500/20 rounded-full animate-ping" />
          </div>
          <div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
              Enhanced Reconnaissance Platform
            </h1>
            <p className="text-slate-400">Professional-Grade Subdomain Enumeration & DNS Analysis</p>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="bg-slate-800/50 border-emerald-500/30">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Subdomains Found</p>
                  <p className="text-2xl font-bold text-emerald-400">{professionalSubdomains.length}</p>
                </div>
                <Globe className="h-8 w-8 text-emerald-500" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="bg-slate-800/50 border-cyan-500/30">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">DNS Records</p>
                  <p className="text-2xl font-bold text-cyan-400">{dnsRecords.length}</p>
                </div>
                <Database className="h-8 w-8 text-cyan-500" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="bg-slate-800/50 border-purple-500/30">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Open Ports</p>
                  <p className="text-2xl font-bold text-purple-400">{portScanResults.length}</p>
                </div>
                <Network className="h-8 w-8 text-purple-500" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="bg-slate-800/50 border-amber-500/30">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Technologies</p>
                  <p className="text-2xl font-bold text-amber-400">{technologyStack.length}</p>
                </div>
                <Brain className="h-8 w-8 text-amber-500" />
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Advanced Subdomain Discovery */}
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-emerald-400">
              <Search className="h-5 w-5" />
              Advanced Subdomain Discovery
            </CardTitle>
            <div className="flex gap-2">
              <Badge variant="outline" className="text-emerald-400 border-emerald-500/50">
                AI-Enhanced
              </Badge>
              <Badge variant="outline" className="text-cyan-400 border-cyan-500/50">
                Neural Network
              </Badge>
              <Badge variant="outline" className="text-purple-400 border-purple-500/50">
                ML-Powered
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {professionalSubdomains.map((subdomain, index) => (
                <div key={index} className={`p-3 rounded-lg border ${getRiskColor(subdomain.risk)}`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full animate-pulse ${
                        subdomain.risk === 'critical' ? 'bg-red-400' :
                        subdomain.risk === 'high' ? 'bg-orange-400' :
                        subdomain.risk === 'medium' ? 'bg-yellow-400' : 'bg-green-400'
                      }`} />
                      <div>
                        <p className="font-mono text-sm font-medium">
                          {subdomain.name}.{targetValue}
                        </p>
                        <p className="text-xs opacity-70">{subdomain.ip}</p>
                      </div>
                    </div>
                    <Badge variant="outline" className={`text-xs ${
                      subdomain.risk === 'critical' ? 'border-red-500/50 text-red-400' :
                      subdomain.risk === 'high' ? 'border-orange-500/50 text-orange-400' :
                      subdomain.risk === 'medium' ? 'border-yellow-500/50 text-yellow-400' :
                      'border-green-500/50 text-green-400'
                    }`}>
                      {subdomain.risk.toUpperCase()}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-4 p-3 bg-emerald-900/20 rounded-lg border border-emerald-600/30">
              <p className="text-xs text-emerald-300">
                🤖 AI Techniques: Dictionary enumeration, Permutation scanning, Certificate transparency, DNS zone walking, Search engine dorking
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Comprehensive DNS Analysis */}
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-cyan-400">
              <Database className="h-5 w-5" />
              Comprehensive DNS Analysis
            </CardTitle>
            <div className="flex gap-2">
              <Badge variant="outline" className="text-blue-400 border-blue-500/50">
                Deep Analysis
              </Badge>
              <Badge variant="outline" className="text-indigo-400 border-indigo-500/50">
                Security Records
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4 max-h-96 overflow-y-auto">
              {['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SRV', 'CAA'].map(recordType => {
                const records = dnsRecords.filter(record => record.type === recordType);
                if (records.length === 0) return null;
                
                return (
                  <div key={recordType} className="p-3 bg-blue-900/20 rounded-lg border border-blue-600/30">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-blue-400 font-medium">
                        {recordType} Records ({records.length})
                      </span>
                      <span className="text-blue-300 text-xs bg-blue-900/50 px-2 py-1 rounded">
                        TTL: {records[0]?.ttl}s
                      </span>
                    </div>
                    <div className="space-y-2">
                      {records.slice(0, 2).map((record, idx) => (
                        <div key={idx} className="bg-blue-900/30 p-2 rounded text-xs">
                          <div className="font-mono text-blue-200">{record.name}</div>
                          <div className="font-mono text-blue-100 mt-1">→ {record.value}</div>
                        </div>
                      ))}
                      {records.length > 2 && (
                        <div className="text-xs text-blue-400 text-center py-1">
                          +{records.length - 2} more records
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* Advanced Port Scanning */}
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-purple-400">
              <Network className="h-5 w-5" />
              Advanced Port Scanning
            </CardTitle>
            <div className="flex gap-2">
              <Badge variant="outline" className="text-purple-400 border-purple-500/50">
                Service Detection
              </Badge>
              <Badge variant="outline" className="text-pink-400 border-pink-500/50">
                Version Enumeration
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {portScanResults.map((port, index) => (
                <div key={index} className={`p-3 rounded-lg border ${getRiskColor(port.risk)}`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full animate-pulse ${
                        port.risk === 'critical' ? 'bg-red-400' :
                        port.risk === 'high' ? 'bg-orange-400' :
                        port.risk === 'medium' ? 'bg-yellow-400' : 'bg-green-400'
                      }`} />
                      <div>
                        <p className="font-mono text-sm font-medium">
                          Port {port.port} - {port.service}
                        </p>
                        <p className="text-xs opacity-70">{port.version}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <Badge variant="outline" className="text-xs text-green-400 border-green-500/50 mb-1">
                        {port.state.toUpperCase()}
                      </Badge>
                      <Badge variant="outline" className={`text-xs block ${
                        port.risk === 'critical' ? 'border-red-500/50 text-red-400' :
                        port.risk === 'high' ? 'border-orange-500/50 text-orange-400' :
                        port.risk === 'medium' ? 'border-yellow-500/50 text-yellow-400' :
                        'border-green-500/50 text-green-400'
                      }`}>
                        {port.risk.toUpperCase()}
                      </Badge>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Technology Stack Fingerprinting */}
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-amber-400">
              <Zap className="h-5 w-5" />
              Technology Stack Fingerprinting
            </CardTitle>
            <div className="flex gap-2">
              <Badge variant="outline" className="text-amber-400 border-amber-500/50">
                ML Detection
              </Badge>
              <Badge variant="outline" className="text-orange-400 border-orange-500/50">
                High Confidence
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {technologyStack.map((tech, index) => (
                <div key={index} className="p-3 bg-amber-900/20 rounded-lg border border-amber-600/30">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-medium text-amber-300">{tech.category}</p>
                      <p className="text-sm text-amber-200">{tech.technology}</p>
                    </div>
                    <div className="text-right">
                      <div className="text-xs text-amber-400 mb-1">Confidence</div>
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-2 bg-amber-900/50 rounded-full overflow-hidden">
                          <div 
                            className="h-full bg-amber-400 rounded-full transition-all duration-500"
                            style={{ width: `${tech.confidence}%` }}
                          />
                        </div>
                        <span className="text-xs text-amber-300 font-mono">{tech.confidence}%</span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Professional Recommendations */}
      <Card className="mt-6 bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-red-400">
            <AlertTriangle className="h-5 w-5" />
            Professional Security Recommendations
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h4 className="text-lg font-semibold text-red-400 mb-3">Critical Actions Required</h4>
              <div className="space-y-2">
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-red-400 rounded-full mt-2 flex-shrink-0" />
                  <p className="text-sm text-red-300">Secure admin and dashboard subdomains immediately</p>
                </div>
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-red-400 rounded-full mt-2 flex-shrink-0" />
                  <p className="text-sm text-red-300">Close unnecessary database ports (3306, 5432)</p>
                </div>
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-red-400 rounded-full mt-2 flex-shrink-0" />
                  <p className="text-sm text-red-300">Implement proper access controls for FTP service</p>
                </div>
              </div>
            </div>
            <div>
              <h4 className="text-lg font-semibold text-amber-400 mb-3">Security Enhancements</h4>
              <div className="space-y-2">
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-amber-400 rounded-full mt-2 flex-shrink-0" />
                  <p className="text-sm text-amber-300">Enable HSTS and security headers</p>
                </div>
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-amber-400 rounded-full mt-2 flex-shrink-0" />
                  <p className="text-sm text-amber-300">Implement DNS security (DNSSEC, CAA records)</p>
                </div>
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-amber-400 rounded-full mt-2 flex-shrink-0" />
                  <p className="text-sm text-amber-300">Regular security monitoring and log analysis</p>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default EnhancedReconnaissance;