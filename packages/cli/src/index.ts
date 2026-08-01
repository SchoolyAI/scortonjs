import process from 'node:process';
import { Command } from 'commander';
import { runScan } from './commands/scan.js';
import { runScore } from './commands/score.js';
import { runAudit } from './commands/audit.js';
import { showConfig, setConfig } from './commands/config.js';
import { initProject } from './commands/init.js';
import { makeReport } from './commands/report.js';
import { runQuiz } from './commands/quiz.js';
import { runSimPhishing } from './commands/sim.js';
import { personaMap } from './commands/persona.js';
import { moduleCreate, moduleList } from './commands/module.js';
import { runCompliance } from './commands/compliance.js';

const program = new Command();
program
  .name('scorton')
  .description('Scorton JS-first CLI with Python providers')
  .version('0.1.0')
  .showHelpAfterError();

program.command('scan')
  .argument('<tool>')
  .argument('<target>')
  .option('--api <url>')
  .option('--token <jwt>')
  .action(runScan);

program.command('score')
  .argument('<target>')
  .option('--api <url>')
  .option('--token <jwt>')
  .action(runScore);

program.command('audit')
  .argument('<target>')
  .option('--api <url>')
  .option('--token <jwt>')
  .action(runAudit);

program.command('config')
  .option('--set <key=value>')
  .action((opts) => {
    if (opts.set) return setConfig(opts.set);
    return showConfig();
  });

program.command('init')
  .option('--template <sector>')
  .action(initProject);

program.command('report')
  .option('--format <fmt>', 'md')
  .action(makeReport);

program.command('quiz').action(runQuiz);
program.command('sim')
  .argument('<type>', 'phishing')
  .option('--email <address>')
  .action(runSimPhishing);

program.command('persona')
  .argument('map')
  .option('--user <name>')
  .action(personaMap);

program.command('compliance')
  .argument('<framework>', 'dora|nis2|both')
  .argument('<target>')
  .option('--api <url>')
  .option('--token <jwt>')
  .action((framework, target, opts) => runCompliance(framework, target, opts));

program.command('module')
  .argument('<action>', 'list')
  .option('--name <name>')
  .action((action, opts) => {
    if (action === 'create') return moduleCreate(opts.name);
    return moduleList();
  });

const args = process.argv.slice(2);

if (args.length === 0) {
  program.help();
  process.exit(0);
}

program.parseAsync(args).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});

