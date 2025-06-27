export interface Logger {
  info: (message?: any, ...optionalParams: any[]) => void;
  log: (message?: any, ...optionalParams: any[]) => void;
  warn: (message?: any, ...optionalParams: any[]) => void;
  debug: (message?: any, ...optionalParams: any[]) => void;
  error: (message?: any, ...optionalParams: any[]) => void;
  fatal: (message?: any, ...optionalParams: any[]) => void;
}

// ANSI escape codes for COLORS
const COLORS = {
  Reset: '\x1b[0m',
  Bright: '\x1b[1m',
  Dim: '\x1b[2m',
  Underscore: '\x1b[4m',
  Blink: '\x1b[5m',
  Reverse: '\x1b[7m',
  Hidden: '\x1b[8m',

  FgBlack: '\x1b[30m',
  FgRed: '\x1b[31m',
  FgGreen: '\x1b[32m',
  FgYellow: '\x1b[33m',
  FgBlue: '\x1b[34m',
  FgMagenta: '\x1b[35m',
  FgCyan: '\x1b[36m',
  FgWhite: '\x1b[37m',
  FgGray: '\x1b[90m',

  BgBlack: '\x1b[40m',
  BgRed: '\x1b[41m',
  BgGreen: '\x1b[42m',
  BgYellow: '\x1b[43m',
  BgBlue: '\x1b[44m',
  BgMagenta: '\x1b[45m',
  BgCyan: '\x1b[46m',
  BgWhite: '\x1b[47m',
  BgGray: '\x1b[100m',
};

class ConsoleLogger implements Logger {
  // private isMuted: boolean = process.env.NODE_ENV === 'test';
  private logs: { level: string; message: any; optionalParams: any[] }[] = [];

  private colorize(level: string, message: string): string {
    switch (level) {
      case 'info':
        return `${COLORS.FgBlue}${message}${COLORS.Reset}`;
      case 'log':
        return message;
      case 'warn':
        return `${COLORS.FgYellow}${message}${COLORS.Reset}`;
      case 'debug':
        return `${COLORS.FgCyan}${message}${COLORS.Reset}`;
      case 'error':
        return `${COLORS.FgRed}${message}${COLORS.Reset}`;
      case 'fatal':
        return `${COLORS.BgRed}${COLORS.FgWhite}${COLORS.Bright}FATAL: ${message}${COLORS.Reset}`;
      default:
        return message;
    }
  }

  private captureLog(level: string, message?: any, optionalParams: any[] = []): void {
    this.logs.push({ level, message, optionalParams });
    const coloredMessage = this.colorize(level, message);
    switch (level) {
      case 'info':
        console.info(coloredMessage, ...optionalParams);
        break;
      case 'log':
        console.log(coloredMessage, ...optionalParams);
        break;
      case 'warn':
        console.warn(coloredMessage, ...optionalParams);
        break;
      case 'debug':
        console.debug(coloredMessage, ...optionalParams);
        break;
      case 'error':
      case 'fatal':
        console.error(coloredMessage, ...optionalParams);
        break;
    }
  }

  info(message?: any, ...optionalParams: any[]): void {
    this.captureLog('info', message, optionalParams);
  }

  log(message?: any, ...optionalParams: any[]): void {
    this.captureLog('log', message, optionalParams);
  }

  warn(message?: any, ...optionalParams: any[]): void {
    this.captureLog('warn', message, optionalParams);
  }

  debug(message?: any, ...optionalParams: any[]): void {
    this.captureLog('debug', message, optionalParams);
  }

  error(message?: any, ...optionalParams: any[]): void {
    this.captureLog('error', message, optionalParams);
  }

  fatal(message?: any, ...optionalParams: any[]): void {
    this.captureLog('fatal', message, optionalParams);
  }

  getLogs(): { level: string; message: any; optionalParams: any[] }[] {
    return this.logs;
  }

  clearLogs(): void {
    this.logs = [];
  }
}

const logger: Logger & {
  getLogs: () => any[];
  clearLogs: () => void;
} = new ConsoleLogger();

export default logger;
