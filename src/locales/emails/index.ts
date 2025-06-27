import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Ajoute ces deux lignes pour obtenir le répertoire courant du fichier
const filename = fileURLToPath(import.meta.url);
const dirname = path.dirname(filename);

type EmailTemplate = { subject: string; html: string };
type EmailTemplates = Record<string, EmailTemplate>;

const cache: Record<string, EmailTemplates> = {};

export function loadEmailTemplates(lang: string): EmailTemplates {
  if (cache[lang]) return cache[lang];
  const filePath = path.join(dirname, `${lang}.json`);
  if (!fs.existsSync(filePath)) throw new Error(`Email template file not found: ${filePath}`);
  const content = fs.readFileSync(filePath, 'utf-8');
  cache[lang] = JSON.parse(content);
  return cache[lang];
}

export function renderTemplate(
  type: string,
  lang: string,
  variables: Record<string, string>,
): EmailTemplate {
  const templates = loadEmailTemplates(lang);
  const tpl = templates[type] || templates['passwordChanged'];
  const interpolate = (str: string) => str.replace(/{{(\w+)}}/g, (_, key) => variables[key] || '');
  return {
    subject: interpolate(tpl.subject),
    html: interpolate(tpl.html),
  };
}
