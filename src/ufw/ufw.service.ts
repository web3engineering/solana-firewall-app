import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface UfwRule {
  ip: string;
  ports: string[]; // Store which of the target ports this IP has access to
  // We might need rule numbers if we want to delete them by number, 
  // but UFW allows deleting by rule specification too.
}

@Injectable()
export class UfwService {
  private readonly logger = new Logger(UfwService.name);
  private readonly targetPorts = ['8899', '11000'];

  // Helper to run UFW commands
  private async runUfwCommand(command: string): Promise<{ stdout: string; stderr: string }> {
    // WARNING: Commands are prefixed with 'sudo'. Ensure your application's
    // user has passwordless sudo rights for these specific ufw commands.
    // This is a significant security consideration.
    const fullCommand = `sudo ${command}`;
    this.logger.log(`Executing UFW command: ${fullCommand}`);
    try {
      const { stdout, stderr } = await execAsync(fullCommand);
      if (stderr) {
        this.logger.warn(`UFW command stderr: ${stderr}`);
      }
      return { stdout, stderr };
    } catch (error) {
      this.logger.error(`Failed to execute UFW command: ${fullCommand}`, error.stack);
      throw new InternalServerErrorException(`UFW command failed: ${error.message}`);
    }
  }

  async getRules(): Promise<UfwRule[]> {
    const { stdout } = await this.runUfwCommand('ufw status numbered');
    const lines = stdout.split('\n');
    const rules: UfwRule[] = [];
    const ipPortMap = new Map<string, Set<string>>();

    // Regex to capture rules like: `[ 1] 8899/tcp ALLOW IN 192.168.1.100` or `[ 2] 11000 ALLOW IN 10.0.0.5`
    // This regex needs to be robust. UFW output can vary.
    // Example line: `[ 1] 22/tcp ALLOW IN Anywhere`
    // Example line for specific IP: `[ 2] 80/tcp ALLOW IN 192.168.1.50`
    // Example for port forward style (less relevant here but good to know): `[ 3]  Anywhere on eth0 ALLOW FWD 10.0.0.0/24 to 192.168.1.10 port 80`
    // We are interested in lines like: `ALLOW IN <ip>` for specific ports.
    // A more specific regex for `ALLOW IN` from a specific IP to one of our target ports:
    // `^\[\s*\d+\]\s+(<port1>|<port2>)(?:/tcp|/udp)?\s+ALLOW IN\s+([\d\.]+)$`
    // Let's try a broader approach first and then filter.

    // This regex captures the rule number, port, action, and IP if present
    const ruleRegex = /^\[\s*(\d+)\]\s+(\S+)\s+(ALLOW IN)\s+(\S+)/i;

    for (const line of lines) {
      const match = line.match(ruleRegex);
      if (match) {
        const ruleNumber = match[1];
        let portPart = match[2]; // Can be <port>, <port>/tcp, <port>/udp
        const action = match[3];
        const ip = match[4];

        // Normalize port (remove /tcp or /udp if present)
        portPart = portPart.split('/')[0];

        if (this.targetPorts.includes(portPart) && ip !== 'Anywhere' && ip !== 'Anywhere (v6)') {
          if (!ipPortMap.has(ip)) {
            ipPortMap.set(ip, new Set<string>());
          }
          ipPortMap.get(ip)!.add(portPart);
        }
      }
    }

    // Convert map to UfwRule array for IPs that have access to *both* target ports
    ipPortMap.forEach((ports, ip) => {
      if (this.targetPorts.every(p => ports.has(p))) {
        rules.push({ ip, ports: Array.from(ports) });
      }
    });

    this.logger.log(`Fetched and parsed UFW rules: ${JSON.stringify(rules)}`);
    return rules;
  }

  async addRule(ip: string, port: string): Promise<void> {
    if (!this.targetPorts.includes(port)) {
        throw new Error(`Port ${port} is not a target port.`);
    }
    // Example: sudo ufw allow from 1.2.3.4 to any port 8899
    await this.runUfwCommand(`ufw allow from ${ip} to any port ${port}`);
    this.logger.log(`Rule added for IP: ${ip}, Port: ${port}`);
  }

  async addRulesForIp(ip: string): Promise<void> {
    for (const port of this.targetPorts) {
        // Check if rule already exists might be good, but ufw handles duplicates gracefully (usually)
        await this.runUfwCommand(`ufw allow from ${ip} to any port ${port}`);
    }
    this.logger.log(`All target port rules added for IP: ${ip}`);
  }

  async deleteRule(ip: string, port: string): Promise<void> {
    if (!this.targetPorts.includes(port)) {
        throw new Error(`Port ${port} is not a target port.`);
    }
    // Example: sudo ufw delete allow from 1.2.3.4 to any port 8899
    await this.runUfwCommand(`ufw delete allow from ${ip} to any port ${port}`);
    this.logger.log(`Rule deleted for IP: ${ip}, Port: ${port}`);
  }

  async deleteRulesForIp(ip: string): Promise<void> {
    for (const port of this.targetPorts) {
        await this.runUfwCommand(`ufw delete allow from ${ip} to any port ${port}`);
    }
    // UFW might require confirmation for delete, or it might just remove. 
    // `ufw --force delete ...` might be needed if it prompts.
    // Also, deleting a non-existent rule is usually fine.
    this.logger.log(`All target port rules deleted for IP: ${ip}`);
  }
}
