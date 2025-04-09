// src/lib/mailer.ts
import nodemailer, { Transporter } from 'nodemailer';
import config from '@/config';
import logger from './logger';

let transporter: Transporter | null = null;

// Initialise le transporter seulement si la configuration est présente
if (config.MAIL_HOST && config.MAIL_PORT && config.MAIL_USER && config.MAIL_PASS) {
  transporter = nodemailer.createTransport({
    host: config.MAIL_HOST,
    port: config.MAIL_PORT,
    secure: config.MAIL_SECURE, // true pour 465, false pour les autres (STARTTLS)
    auth: {
      user: config.MAIL_USER,
      pass: config.MAIL_PASS,
    },
    // Optionnel: Ajouter des options pour les environnements de dev/test
    // tls: {
    //   rejectUnauthorized: config.NODE_ENV === 'production', // Ne pas vérifier le certificat en dev/test si nécessaire
    // },
  });

  // Vérifier la connexion au démarrage (optionnel mais recommandé)
  transporter.verify((error, success) => {
    if (error) {
      logger.error(error, 'Mailer verification failed. Emails might not be sent.');
      transporter = null; // Désactiver si la vérification échoue
    } else {
      logger.info('Mailer is ready to send emails.');
    }
  });
} else {
  logger.warn('Mail service configuration is incomplete. Mailer disabled.');
}

interface MailOptions {
  to: string | string[];
  subject: string;
  text?: string;
  html?: string;
  from?: string; // Utilise MAIL_FROM par défaut si non fourni
}

/**
 * Envoie un email en utilisant le transporter configuré.
 * @param options Options de l'email (to, subject, text, html, from)
 */
export const sendMail = async (options: MailOptions): Promise<void> => {
  if (!transporter) {
    logger.error('Mail transporter is not configured or failed verification. Cannot send email.');
    // Vous pourriez vouloir lancer une erreur ici dans certains cas critiques
    // throw new Error('Mailer is not available');
    return; // Ou simplement ne rien faire
  }

  const mailDefaults = {
    from: options.from || config.MAIL_FROM, // Expéditeur par défaut
  };

  try {
    const info = await transporter.sendMail({ ...mailDefaults, ...options });
    logger.info(`Email sent successfully: ${info.messageId}`);
    // logger.debug({ accepted: info.accepted, rejected: info.rejected, response: info.response }, 'Email delivery details');
  } catch (error) {
    logger.error(error, 'Failed to send email');
    // Gérer l'échec d'envoi (ex: retry, log spécifique)
    throw error; // Relancer l'erreur pour que l'appelant puisse la gérer
  }
};

export default {
  sendMail,
  isReady: () => transporter !== null, // Fonction pour vérifier si le mailer est prêt
};
