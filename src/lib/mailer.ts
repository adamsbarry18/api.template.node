import nodemailer, { Transporter } from 'nodemailer';
import config from '@/config';
import logger from './logger';

let transporter: Transporter | null = null;

if (config.MAIL_HOST && config.MAIL_PORT && config.MAIL_USER && config.MAIL_PASS) {
  try {
    transporter = nodemailer.createTransport({
      host: config.MAIL_HOST,
      port: config.MAIL_PORT,
      secure: false,
      auth: {
        user: config.MAIL_USER,
        pass: config.MAIL_PASS,
      },
      // tls: {
      //   rejectUnauthorized: config.NODE_ENV === 'production',
      // },
    });

    transporter.verify((error, success) => {
      if (error) {
        logger.error(error, 'Mailer verification failed during verify:', error);
        transporter = null;
      } else {
        logger.info('Mailer is ready to send emails.');
      }
    });
  } catch (error) {
    logger.error(error, 'Error during transporter creation:', error);
    transporter = null;
  }
} else {
  logger.warn('Mail service configuration is incomplete. Mailer disabled.');
}

interface MailOptions {
  to: string | string[];
  subject: string;
  text?: string;
  html?: string;
  from?: string;
}

/**
 * Envoie un email en utilisant le transporter configuré.
 * @param options Options de l'email (to, subject, text, html, from)
 */
export const sendMail = async (options: MailOptions): Promise<void> => {
  if (!transporter) {
    logger.error('Mail transporter is not configured or failed verification. Cannot send email.');
    return;
  }

  const mailDefaults = {
    from: options.from || config.MAIL_FROM,
  };

  try {
    const info = await transporter.sendMail({ ...mailDefaults, ...options });
    logger.info(`Email sent successfully: ${info.messageId}`);
  } catch (error) {
    logger.error(error, 'Failed to send email');
    throw error;
  }
};

export default {
  sendMail,
  isReady: () => transporter !== null,
};
