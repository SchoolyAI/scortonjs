const {Command, Flags} = require('@oclif/core');

class HelloCommand extends Command {
  async run() {
    const {flags} = await this.parse(HelloCommand);
    const name = flags.name || 'world';
    this.log(`hello ${name}`);
  }
}

HelloCommand.description = 'Say hello';
HelloCommand.flags = {
  name: Flags.string({char: 'n', description: 'name to print'}),
};

module.exports = HelloCommand;
