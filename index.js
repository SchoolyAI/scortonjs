/**
 * ScortonJS - Main module
 * Provides programmatic access to ScortonJS functionality
 */

const { spawn } = require('child_process');
const path = require('path');

class ScortonJS {
  constructor() {
    this.pythonScript = path.join(__dirname, 'scorton.py');
  }

  /**
   * Execute a scorton command
   * @param {string} command - The command to execute (scan, score, audit, config, help)
   * @param {Array} args - Additional arguments
   * @param {Object} options - Execution options
   * @returns {Promise} Promise that resolves with the command output
   */
  async execute(command, args = [], options = {}) {
    return new Promise((resolve, reject) => {
      const pythonArgs = [command, ...args];
      const pythonCommand = process.env.SCORTON_PY_PATH || 'python';
      
      const pythonProcess = spawn(pythonCommand, [this.pythonScript, ...pythonArgs], {
        stdio: ['pipe', 'pipe', 'pipe'],
        ...options
      });

      let stdout = '';
      let stderr = '';

      pythonProcess.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      pythonProcess.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      pythonProcess.on('close', (code) => {
        if (code === 0) {
          resolve({ stdout, stderr, code });
        } else {
          reject(new Error(`Command failed with code ${code}: ${stderr}`));
        }
      });

      pythonProcess.on('error', (error) => {
        reject(error);
      });
    });
  }

  /**
   * Run a security scan
   * @param {string} tool - The tool to use
   * @param {string} target - The target to scan
   * @param {Object} options - Additional options
   */
  async scan(tool, target, options = {}) {
    const args = [tool, target];
    if (options.api) args.push('--api', options.api);
    if (options.token) args.push('--token', options.token);
    
    return this.execute('scan', args);
  }

  /**
   * Calculate Cyberscore
   * @param {string} target - The target to score
   * @param {Object} options - Additional options
   */
  async score(target, options = {}) {
    const args = [target];
    if (options.api) args.push('--api', options.api);
    if (options.token) args.push('--token', options.token);
    
    return this.execute('score', args);
  }

  /**
   * Run deep audit
   * @param {string} target - The target to audit
   * @param {Object} options - Additional options
   */
  async audit(target, options = {}) {
    const args = [target];
    if (options.api) args.push('--api', options.api);
    if (options.token) args.push('--token', options.token);
    
    return this.execute('audit', args);
  }

  /**
   * Show configuration
   * @param {Object} options - Additional options
   */
  async config(options = {}) {
    const args = [];
    if (options.set) args.push('--set', options.set);
    
    return this.execute('config', args);
  }
}

module.exports = ScortonJS;
